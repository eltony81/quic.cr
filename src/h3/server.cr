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
  # When using `listen`, the server manages its own QUIC::Server + UDP loop.
  class Server
    Log = ::Log.for("H3::Server")

    # Low-level handler type (backwards-compatible).
    alias LowLevelHandler = Proc(Hash(String, String), Bytes, {Hash(String, String), Bytes})

    @low_level_handler : LowLevelHandler?
    @router : H3::Router?

    # ------------------------------------------------------------------ Constructors

    # Mode 1: low-level block handler.
    def initialize(&handler : Hash(String, String), Bytes -> {Hash(String, String), Bytes})
      @low_level_handler = handler
    end

    # Mode 2: router-based.
    def initialize(router : H3::Router)
      @router = router
    end

    # ------------------------------------------------------------------ Blocking listen

    # Starts a fully managed QUIC/UDP server loop.
    #
    # Parameters:
    # - host       — bind address (default "0.0.0.0")
    # - port       — UDP port (default 4433)
    # - cert       — path to TLS certificate PEM
    # - key        — path to TLS private key PEM
    # - max_data   — connection-level flow control window (default 10 MB)
    def listen(
      host     : String      = "0.0.0.0",
      port     : Int32       = 4433,
      cert     : String      = "cert.pem",
      key      : String      = "key.pem",
      max_data : UInt64      = 10_000_000_u64
    )
      config = QUIC::Config.new
      config.cert_file                         = cert
      config.key_file                          = key
      config.initial_max_data                  = max_data == 10_000_000_u64 ? 50_000_000_u64 : max_data
      config.initial_max_stream_data_bidi_local  = 10_000_000_u64
      config.initial_max_stream_data_bidi_remote = 10_000_000_u64
      config.initial_max_streams_bidi          = 128_u64
      config.initial_max_streams_uni           = 128_u64
      config.initial_max_stream_data_uni       = 10_000_000_u64

      udp = UDPSocket.new
      udp.bind(host, port)
      Log.info { "🚀 HTTP/3 Server listening on udp://#{host}:#{port}" }

      connections     = {} of String => {QUIC::Connection, H3::Connection, Socket::IPAddress}
      handled_streams = Set(Tuple(String, UInt64)).new
      
      event_chan = Channel(Tuple(Symbol, Bytes | String, Socket::IPAddress)).new(1000)

      buf_pool = QUIC::BufferPool.new

      # Spawn background receiver fiber
      spawn do
        loop do
          buf = buf_pool.lease
          begin
            size, client_addr = udp.receive(buf)
            # Copy only the received bytes; return the leased buffer immediately
            packet_data = buf[0, size].dup
            buf_pool.return(buf)
            event_chan.send({:packet, packet_data.as(Bytes | String), client_addr})
          rescue e
            buf_pool.return(buf)
            break if udp.closed?
          end
        end
      end

      out_buf = Bytes.new(65536)

      loop do
        select
        when event = event_chan.receive
          event_type, payload, client_addr = event
          if event_type == :packet
            packet_data = payload.as(Bytes)
            conn_key   = extract_dcid(packet_data)
            Log.info { "Processing packet for conn_key: #{conn_key} (size: #{packet_data.size})" }
            conn_tuple = connections[conn_key]?

            if conn_tuple.nil?
              Log.debug { "New connection (DCID: #{conn_key})" }
              quic_conn = QUIC::Connection.new(config, is_server: true)
              h3_conn   = H3::Connection.new(quic_conn)
              conn_tuple = {quic_conn, h3_conn, client_addr}
              connections[conn_key] = conn_tuple
            end

            quic_conn, h3_conn, prev_addr = conn_tuple

            # RFC 9000 §9: detect connection migration (peer address change)
            if prev_addr != client_addr && quic_conn.handshake_complete?
              Log.info { "Connection migration: #{prev_addr} → #{client_addr}" }
              quic_conn.initiate_path_validation
            end

            # Update current remote address in connection tuple
            conn_tuple = {quic_conn, h3_conn, client_addr}
            connections[conn_key] = conn_tuple

            was_completed = quic_conn.handshake_complete?
            quic_conn.recv(packet_data)

            # Map the server-chosen Source Connection ID (SCID) to the same connection
            if scid = quic_conn.scid
              connections[scid.hexstring] = conn_tuple
            end

            # Send control, QPACK encoder, and decoder streams upon handshake completion
            if !was_completed && quic_conn.handshake_complete?
              begin
                ctrl = h3_conn.open_uni_stream(0_u64)
                sf   = H3::SettingsFrame.new
                sf.settings = {0x01_u64 => 0_u64, 0x07_u64 => 100_u64, 0x06_u64 => 100_u64}
                h3_conn.write_frame(ctrl, sf)
                h3_conn.open_qpack_streams
              rescue e
                Log.error { "Failed to initialize server control stream: #{e.message}" }
              end
            end

            # Dispatch new client-initiated bidirectional streams (ID % 4 == 0)
            quic_conn.streams.each do |stream_id, _stream|
              next unless stream_id % 4 == 0
              stream_key = {conn_key, stream_id}
              next if handled_streams.includes?(stream_key)
              handled_streams << stream_key

              sock = QUIC::StreamSocket.new(quic_conn, stream_id)
              spawn do
                begin
                  handle_request(h3_conn, sock)
                  Log.debug { "Handled stream #{stream_id}" }
                rescue e
                  Log.error { "Stream #{stream_id} error: #{e.class} — #{e.message}" }
                ensure
                  event_chan.send({:send, conn_key.as(Bytes | String), client_addr})
                end
              end
            end

            while (n = quic_conn.send(out_buf)) > 0
              udp.send(out_buf[0, n], client_addr)
            end
          elsif event_type == :send
            conn_key = payload.as(String)
            Log.info { "Processing send event for conn_key: #{conn_key}" }
            if conn_tuple = connections[conn_key]?
              quic_conn, _, _ = conn_tuple
              sent_any = false
              while (n = quic_conn.send(out_buf)) > 0
                udp.send(out_buf[0, n], client_addr)
                Log.info { "Sent #{n} bytes to #{client_addr}" }
                sent_any = true
              end
              Log.info { "Send loop finished, sent_any = #{sent_any}" }
            else
              Log.info { "Connection not found for key: #{conn_key}" }
            end
          end
          nil

        when timeout(10.milliseconds)
          connections.each_value do |tuple|
            quic_conn, _, client_addr = tuple
            quic_conn.tick
            while (n = quic_conn.send(out_buf)) > 0
              udp.send(out_buf[0, n], client_addr)
            end
          end
          nil
        end
      end
    rescue e : Exception
      Log.error { "Server fatal error: #{e.message}\n#{e.backtrace.join("\n")}" }
    end

    # ------------------------------------------------------------------ Request dispatch

    # Handles a single request on the given stream IO.
    # Called internally by `listen` and directly in unit tests.
    def handle_request(h3_conn : H3::Connection, stream : IO, remote_address : String = "")
      req_frame = h3_conn.read_frame(stream)
      return unless req_frame.is_a?(HeadersFrame)

      body_io = IO::Memory.new
      loop do
        begin
          nxt = h3_conn.read_frame(stream)
          if nxt.is_a?(DataFrame)
            body_io.write(nxt.data)
          elsif nxt.is_a?(HeadersFrame)
            # Stop if we hit a HeadersFrame (trailers)
            break
          else
            break
          end
        rescue
          break
        end
      end
      body = body_io.to_slice

      if router = @router
        # ---- Mode 2: Router-based dispatch ----------------------------------
        request  = H3::Request.new(req_frame.headers, body, remote_address)
        response = H3::Response.new
        ctx      = H3::Context.new(request, response)

        unless router.dispatch(ctx)
          ctx.not_found
        end

        h3_conn.write_frame(stream, HeadersFrame.new(response.to_h3_headers))
        body_bytes = response.body_bytes
        h3_conn.write_frame(stream, DataFrame.new(body_bytes)) unless body_bytes.empty?

      elsif handler = @low_level_handler
        # ---- Mode 1: Low-level block handler (backwards-compatible) ---------
        resp_headers, resp_body = handler.call(req_frame.headers, body)
        h3_conn.write_frame(stream, HeadersFrame.new(resp_headers))
        h3_conn.write_frame(stream, DataFrame.new(resp_body)) unless resp_body.empty?
      end

      if stream.responds_to?(:close_local)
        stream.close_local
      end
    end

    # ------------------------------------------------------------------ Private

    private def extract_dcid(data : Bytes) : String
      io       = IO::Memory.new(data)
      first    = io.read_byte || 0_u8
      is_long  = (first & 0x80) != 0
      if is_long
        io.skip(4)   # version
        len  = io.read_byte || 0_u8
        dcid = Bytes.new(len)
        io.read_fully(dcid)
        dcid.hexstring
      else
        dcid = Bytes.new(8)
        io.read_fully(dcid)
        dcid.hexstring
      end
    rescue
      "unknown"
    end
  end
end
