require "socket"
require "uri"

module H3
  # High-level HTTP/3 server with two operation modes:
  #
  # **Mode 1 — Low-level handler block** (backwards-compatible):
  #
  #   server = H3::Server.new do |headers, body|
  #     { {":status" => "200"}, "hello".to_slice }
  #   end
  #
  # **Mode 2 — Router-based** (full middleware + routing DSL):
  #
  #   router = H3::Router.new
  #   router.use { |ctx, nxt| Log.info { ctx.request.path }; nxt.call(ctx) }
  #   router.get "/" { |ctx| ctx.text "Hello!" }
  #   router.get "/users/:id" { |ctx| ctx.json %({"id":"#{ctx.request.path_params["id"]}"}) }
  #
  #   H3::Server.new(router).listen("0.0.0.0", 4433, cert: "cert.pem", key: "key.pem")
  #
  # When using `listen`, each QUIC connection is owned by a dedicated actor fiber
  # (ConnectionActor). With --flag preview_mt, actors run on multiple OS threads.
  class Server
    Log = ::Log.for("H3::Server")

    alias LowLevelHandler = Proc(Hash(String, String), Bytes, {Hash(String, String), Bytes})

    @low_level_handler : LowLevelHandler?
    @router : H3::Router?
    @shutdown_flag = Atomic(Bool).new(false)
    @udp_socket : UDPSocket? = nil

    def shutdown
      @shutdown_flag.set(true)
      @udp_socket.try &.close rescue nil
    end

    def initialize(&handler : Hash(String, String), Bytes -> {Hash(String, String), Bytes})
      @low_level_handler = handler
    end

    def initialize(router : H3::Router)
      @router = router
    end

    def listen(
      host     : String = "0.0.0.0",
      port     : Int32  = 4433,
      cert     : String = "cert.pem",
      key      : String = "key.pem",
      max_data : UInt64 = 10_000_000_u64
    )
      config = QUIC::Config.new
      config.cert_file                           = cert
      config.key_file                            = key
      config.initial_max_data                    = max_data == 10_000_000_u64 ? 50_000_000_u64 : max_data
      config.initial_max_stream_data_bidi_local  = 10_000_000_u64
      config.initial_max_stream_data_bidi_remote = 10_000_000_u64
      config.initial_max_streams_bidi            = 128_u64
      config.initial_max_streams_uni             = 128_u64
      config.initial_max_stream_data_uni         = 10_000_000_u64

      udp = UDPSocket.new
      udp.reuse_port = true
      udp.bind(host, port)
      # ECN: mark outgoing UDP datagrams as ECT(0) so network routers can signal
      # congestion via CE marks in ACK frames instead of dropping packets
      # (RFC 9000 §13.4, RFC 9002 §7.6).
      tos = 2  # ECT(0) = 0x02
      LibC.setsockopt(udp.fd, LibSys::IPPROTO_IP, LibSys::IP_TOS, pointerof(tos).as(Void*), sizeof(Int32).to_u32)
      @udp_socket = udp
      batch_receiver = QUIC::BatchReceiver.new(udp)
      # GRO merges equal-size QUIC packets into one large buffer per recvmmsg slot.
      # blocking_drain reads the UDP_GRO cmsg to learn gso_size and each_segment
      # splits the buffer correctly. On loopback (Linux 6.1) the kernel accepts
      # UDP_GRO but does not coalesce, so each_segment falls back to single-packet
      # mode transparently when msg_controllen=0.
      batch_receiver.enable_gro!(udp)
      Log.info { "🚀 HTTP/3 Server listening on udp://#{host}:#{port}" }

      # Router-only state — never touched by actor fibers (no mutex needed).
      connections = {} of String => ConnectionActor

      # Single RouterMsg channel avoids Crystal's select union-type merging.
      # Struct wrappers give the case/when branches distinct types to narrow on.
      router_chan = Channel(RouterMsg).new(4096 + 512)

      # Receiver fiber: blocking_drain waits via IO.select (fiber-aware epoll),
      # then drains all buffered packets with recvmmsg MSG_DONTWAIT. With GRO,
      # each slot may hold N coalesced packets; each_segment splits them by gso_size.
      spawn do
        loop do
          begin
            n = batch_receiver.blocking_drain(udp)
            n.times do |i|
              batch_receiver.each_segment(i) do |data, addr|
                router_chan.send(RouterPacket.new(data, addr))
              end
            end
          rescue e
            break if udp.closed?
            Log.debug { "recv error: #{e.message}" }
          end
        end
      end

      # Router loop — single fiber, sole owner of `connections`.
      # Struct-tagged messages dispatch cleanly without select type merging.
      loop do
        break if @shutdown_flag.get
        msg = router_chan.receive
        break if @shutdown_flag.get
        case msg
        when RouterPacket
          data     = msg.data
          addr     = msg.addr
          conn_key = extract_dcid(data)
          addr_key = addr.to_s

          # Primary lookup by DCID; fallback to source addr for packets that
          # arrive before the actor's RouterReg (new SCID) is processed.
          # Race: the actor sends its RouterReg then flushes the ServerHello
          # in the same fiber turn. Python sends a Handshake (DCID=server SCID)
          # ~1ms later, but the RouterReg isn't processed until all 8 actor
          # fibers yield — potentially 8ms. addr_key is stable across the
          # entire connection life, so it acts as a safe fallback.
          actor = connections[conn_key]? || connections[addr_key]?
          if actor.nil?
            # Short-header from unknown DCID → stateless reset (RFC 9000 §10.3).
            # The peer has lost our state; we respond with a deterministic HMAC
            # token derived from the DCID so the peer recognises the reset without
            # requiring us to store any per-connection state.
            if !data.empty? && (data[0] & 0x80_u8) == 0
              dcid_bytes = data.size >= 9 ? data[1, 8] : Bytes.empty
              token = QUIC::AddressValidation.stateless_reset_token(dcid_bytes)
              reset_pkt = Bytes.new(40)
              reset_pkt[0] = 0x40_u8 | Random::Secure.rand(64).to_u8
              Random::Secure.random_bytes(reset_pkt[1, 23])
              reset_pkt[24, 16].copy_from(token)
              udp.send(reset_pkt, addr) rescue nil
              next
            end
            quic_conn = QUIC::Connection.new(config, is_server: true)
            h3_conn   = H3::Connection.new(quic_conn)
            actor = ConnectionActor.new(
              quic_conn, h3_conn, addr, udp, self,
              router_chan, conn_key
            )
            connections[conn_key] = actor
            connections[addr_key]  = actor
          elsif !connections[conn_key]?
            # DCID is a new SCID not yet registered — cache it for fast future lookup.
            connections[conn_key] = actor
          end
          actor.deliver(data)

        when RouterReg
          connections[msg.key] = msg.actor

        when RouterClean
          connections.delete(msg.key)
          connections.delete(msg.addr_key)
        end
      end
      connections.each_value do |actor|
        actor.shutdown rescue nil
      end
    rescue e : Exception
      Log.error { "Server fatal error: #{e.message}\n#{e.backtrace.join("\n")}" } unless @shutdown_flag.get
    end

    # ── Request dispatch ───────────────────────────────────────────────────────

    # Handles a single request on the given stream IO.
    # Called internally by ConnectionActor and directly in unit tests.
    def handle_request(h3_conn : H3::Connection, stream : IO, remote_address : String = "")
      # Read first frame — QPACK::ValidationError bubbles up as H3_MESSAGE_ERROR.
      req_frame = begin
        h3_conn.read_frame(stream)
      rescue e : QPACK::ValidationError
        h3_conn.quic.close(H3::ErrorCode::H3_MESSAGE_ERROR, e.message || "header validation error")
        return
      rescue e
        Log.debug { "H3 request: failed to read first frame: #{e.class} — #{e.message}" }
        return
      end

      # Reject wrong frame types before the first HEADERS (RFC 9114 §4.1, §7.2).
      case req_frame
      when DataFrame
        h3_conn.quic.close(H3::ErrorCode::H3_FRAME_UNEXPECTED, "DATA frame before HEADERS on request stream")
        return
      when SettingsFrame
        h3_conn.quic.close(H3::ErrorCode::H3_FRAME_UNEXPECTED, "SETTINGS frame on request stream")
        return
      when PushPromiseFrame
        h3_conn.quic.close(H3::ErrorCode::H3_ID_ERROR, "client MUST NOT send PUSH_PROMISE")
        return
      end
      return unless req_frame.is_a?(HeadersFrame)

      # Validate required request pseudo-headers (RFC 9114 §4.3.1).
      hdrs = req_frame.headers
      unless hdrs.has_key?(":method") && hdrs.has_key?(":path") && hdrs.has_key?(":scheme")
        h3_conn.quic.close(H3::ErrorCode::H3_MESSAGE_ERROR, "missing required request pseudo-header")
        return
      end
      # :status is a response-only pseudo-header — illegal in a request.
      if hdrs.has_key?(":status")
        h3_conn.quic.close(H3::ErrorCode::H3_MESSAGE_ERROR, ":status pseudo-header in request")
        return
      end

      body_io = IO::Memory.new
      loop do
        begin
          nxt = h3_conn.read_frame(stream)
          case nxt
          when DataFrame
            body_io.write(nxt.data)
          when HeadersFrame
            break  # trailers — body reading stops here
          when SettingsFrame
            h3_conn.quic.close(H3::ErrorCode::H3_FRAME_UNEXPECTED, "SETTINGS frame on request stream")
            return
          when PushPromiseFrame
            h3_conn.quic.close(H3::ErrorCode::H3_ID_ERROR, "client MUST NOT send PUSH_PROMISE")
            return
          else
            break
          end
        rescue e
          Log.debug { "H3 request: body frame read interrupted: #{e.message}" }
          break
        end
      end
      body = body_io.to_slice

      if router = @router
        # ---- Mode 2: Router-based dispatch ----------------------------------
        request  = H3::Request.new(req_frame.headers, body, remote_address)
        response = H3::Response.new
        ctx      = H3::Context.new(request, response)
        ctx.h3_conn = h3_conn
        ctx.request_stream_id = stream.responds_to?(:stream_id) ? stream.stream_id : nil

        begin
          unless router.dispatch(ctx)
            ctx.not_found
          end
        rescue e
          Log.error(exception: e) { "Handler exception — #{request.method} #{request.path}" }
          ctx.response.text("Internal Server Error", 500)
        end

        h3_conn.write_response(stream, ctx.response.to_h3_headers, ctx.response.body_bytes)

      elsif handler = @low_level_handler
        # ---- Mode 1: Low-level block handler (backwards-compatible) ---------
        begin
          resp_headers, resp_body = handler.call(req_frame.headers, body)
          h3_conn.write_response(stream, resp_headers, resp_body)
        rescue e
          Log.error(exception: e) { "Low-level handler exception" }
          error_resp = {":status" => "500"}
          h3_conn.write_response(stream, error_resp)
        end
      end

      if stream.responds_to?(:close_local)
        stream.close_local
      end
    end

    # Handles a client-initiated unidirectional stream: reads the stream type and
    # dispatches to the appropriate handler (QPACK encoder/decoder, control, etc.).
    def handle_uni_stream(h3_conn : H3::Connection, stream : IO)
      type = QUIC::VarInt.decode(stream)
      case type
      when 0x02  # QPACK encoder stream: client sends dynamic table insertions
        buf = Bytes.new(4096)
        loop do
          n = stream.read(buf)
          break if n == 0
          h3_conn.process_encoder_stream(buf[0, n])
        end
      when 0x03  # QPACK decoder stream: client acknowledges our encoder instructions
        buf = Bytes.new(512)
        loop { break if stream.read(buf) == 0 }
      when 0x00  # Control stream: client sends SETTINGS and other control frames
        loop do
          begin
            frame = H3::Frame.decode(stream, nil)
            case frame
            when H3::SettingsFrame
              # Apply peer's QPACK_MAX_TABLE_CAPACITY to our encoder (RFC 9204 §3.2).
              h3_conn.apply_remote_settings(frame.settings)
            when H3::GoAwayFrame
              h3_conn.peer_goaway_stream_id = frame.stream_id
            when H3::MaxPushIdFrame
              # Track the highest push ID the client will accept (RFC 9114 §4.6).
              cur = h3_conn.peer_max_push_id
              h3_conn.peer_max_push_id = cur ? Math.max(cur, frame.push_id) : frame.push_id
            end
          rescue e
            Log.debug { "Control stream decode stopped: #{e.message}" }
            break
          end
        end
      else
        # Unknown stream type — RFC requires ignoring
        buf = Bytes.new(512)
        loop { break if stream.read(buf) == 0 }
      end
    rescue e
      if stream.responds_to?(:stream_id)
        Log.debug { "Uni-stream (#{stream.stream_id}) closed: #{e.message}" }
      else
        Log.debug { "Uni-stream closed: #{e.message}" }
      end
    end

    # ── Private ────────────────────────────────────────────────────────────────

    private def extract_dcid(data : Bytes) : String
      return "unknown" if data.empty?
      first = data[0]
      is_long = (first & 0x80) != 0
      if is_long
        return "unknown" if data.size < 6
        len = data[5].to_i
        return "unknown" if data.size < 6 + len
        data[6, len].hexstring
      else
        return "unknown" if data.size < 9
        data[1, 8].hexstring
      end
    rescue e
      Log.debug { "extract_dcid failed: #{e.message}" }
      "unknown"
    end
  end
end
