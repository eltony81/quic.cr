require "socket"
require "../quic/batch_sender"

module H3
  # Tagged message structs for the router event channel.
  # Struct wrappers avoid Crystal's union-tuple type erasure that occurs
  # when Tuple variants are stored in a union Channel.
  record RouterPacket, data : Bytes, addr : Socket::IPAddress
  record RouterReg,    key : String, actor : ConnectionActor
  record RouterClean,  key : String, addr_key : String
  alias RouterMsg = RouterPacket | RouterReg | RouterClean

  # Per-connection actor: owns QUIC::Connection exclusively in one fiber.
  # No mutex needed — all state is local to this fiber's run loop.
  # With -Dpreview_mt, different actors run on different OS threads.
  class ConnectionActor
    Log = ::Log.for("H3::ConnectionActor")

    getter packet_chan   : Channel(Bytes)
    getter response_chan : Channel({UInt64, Bytes})

    @quic_conn    : QUIC::Connection
    @h3_conn      : H3::Connection
    @peer_addr    : Socket::IPAddress
    @udp          : UDPSocket
    @server       : H3::Server
    @router_chan  : Channel(RouterMsg)   # SCID alias + cleanup → router
    @initial_key  : String

    @stream_channels  = {} of UInt64 => Channel(Bytes)
    @stream_eof_sent  = Set(UInt64).new
    @handled_streams  = Set(UInt64).new
    @scid_registered  = false
    @out_buf          : Bytes
    @fwd_buf          : Bytes
    @batch_sender     : QUIC::BatchSender

    def initialize(
      @quic_conn, @h3_conn, @peer_addr, @udp, @server,
      @router_chan, @initial_key
    )
      @packet_chan   = Channel(Bytes).new(512)
      @response_chan = Channel({UInt64, Bytes}).new(256)
      @out_buf = Bytes.new(65536)
      @fwd_buf = Bytes.new(65536)
      @batch_sender = QUIC::BatchSender.new(@udp)
      spawn(name: "actor-#{@initial_key[0, 8]}") { run }
    end

    def deliver(data : Bytes)
      select
      when @packet_chan.send(data)
      else
        Log.warn { "Actor #{@initial_key[0, 8]}: packet_chan full (cap=512), dropping packet" }
      end
    end

    private def run
      loop do
        select
        when data = @packet_chan.receive
          recv_packet(data)
          # Non-blocking drain: use select+else, which is Crystal's true
          # try-receive. Channel#receive? blocks until closed — not what we want.
          loop do
            drained = false
            select
            when pending = @packet_chan.receive
              drained = true
              recv_packet(pending)
            else
            end
            break unless drained
          end
          flush_outgoing

        when resp = @response_chan.receive
          handle_response(resp[0], resp[1])

        when timeout(10.milliseconds)
          @quic_conn.tick
          flush_outgoing
        end
        break if @quic_conn.closed?
      end
    rescue e
      Log.error { "Actor #{@initial_key[0, 8]} crashed: #{e.class} — #{e.message}" }
    ensure
      @stream_channels.each_value do |ch|
        select
        when ch.send(Bytes.empty)
        else
        end
      end
      select
      when @router_chan.send(RouterClean.new(@initial_key, @peer_addr.to_s))
      else
      end
    end

    private def recv_packet(data : Bytes)
      was_completed = @quic_conn.handshake_complete?
      @quic_conn.recv(data)

      unless @scid_registered
        if scid = @quic_conn.scid
          new_key = scid.hexstring
          if new_key != @initial_key
            @router_chan.send(RouterReg.new(new_key, self))
            @scid_registered = true
          end
        end
      end

      if !was_completed && @quic_conn.handshake_complete?
        init_h3_control_streams
      end

      dispatch_new_streams
      forward_stream_data
    end

    private def handle_response(stream_id : UInt64, data : Bytes)
      if stream = @quic_conn.streams[stream_id]?
        stream.write(data)
        stream.close_local
      end
      flush_outgoing
    end

    # Drains received bytes from each stream into its handler channel.
    # Only this actor ever calls stream.read — no mutex needed.
    private def forward_stream_data
      @quic_conn.streams.each do |stream_id, stream|
        next unless chan = @stream_channels[stream_id]?
        next if @stream_eof_sent.includes?(stream_id)

        loop do
          n = stream.read(@fwd_buf)
          break if n == 0
          chan.send(@fwd_buf[0, n].dup)
        end

        state = stream.state
        if state.half_closed_remote? || state.closed?
          chan.send(Bytes.empty)
          @stream_eof_sent << stream_id
        end
      end
    end

    private def dispatch_new_streams
      @quic_conn.streams.each do |stream_id, _|
        next if @handled_streams.includes?(stream_id)

        if stream_id % 4 == 0
          # Client-initiated bidirectional: HTTP/3 request
          @handled_streams << stream_id
          data_chan = Channel(Bytes).new(512)
          @stream_channels[stream_id] = data_chan
          sock = ActorStreamSocket.new(stream_id, data_chan, self)
          spawn(name: "req-#{stream_id}") do
            @server.handle_request(@h3_conn, sock)
            sock.close_local
          end

        elsif stream_id % 4 == 2
          # Client-initiated unidirectional: QPACK encoder / decoder / control
          @handled_streams << stream_id
          data_chan = Channel(Bytes).new(16)
          @stream_channels[stream_id] = data_chan
          sock = ActorStreamSocket.new(stream_id, data_chan, self)
          spawn(name: "uni-#{stream_id}") { @server.handle_uni_stream(@h3_conn, sock) }
        end
      end
    end

    private def flush_outgoing
      loop do
        n = @quic_conn.send_coalesced(@out_buf)
        break if n == 0
        @udp.send(@out_buf[0, n], @peer_addr)
      end
    rescue

    end

    private def init_h3_control_streams
      ctrl = @h3_conn.open_control_stream
      sf   = H3::SettingsFrame.new
      # 0x01 = QPACK_MAX_TABLE_CAPACITY = 4096 (peers may use the dynamic table with us)
      # 0x07 = QPACK_BLOCKED_STREAMS, 0x06 = MAX_FIELD_SECTION_SIZE
      sf.settings = {0x01_u64 => 4096_u64, 0x07_u64 => 100_u64, 0x06_u64 => 16384_u64}
      @h3_conn.write_frame(ctrl, sf)
      @h3_conn.open_qpack_streams
      flush_outgoing
    rescue e
      Log.error { "H3 control stream init failed: #{e.message}" }
    end
  end
end
