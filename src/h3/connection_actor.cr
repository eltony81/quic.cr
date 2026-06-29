require "socket"
require "../quic/batch_sender"
require "./response_ring"

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

    getter packet_chan : Channel(Bytes)

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
    @goaway_pending   : Bool = false
    @response_ring    : ResponseRing
    # Single-element wake channel: handler fibers do a non-blocking send after
    # pushing to response_ring so the actor's select unblocks promptly.
    @wake_chan        : Channel(Nil)
    # Pacing token bucket: tokens represent bytes we are allowed to send right now.
    # Starts unlimited so the handshake and initial burst are never throttled.
    @pacing_tokens    : Float64 = Float64::MAX
    @pacing_refill_at : Time::Instant = Time.instant
    # Optional callback invoked when the actor's run loop exits (used by drain).
    @on_close         : (-> Nil)?

    def initialize(
      @quic_conn, @h3_conn, @peer_addr, @udp, @server,
      @router_chan, @initial_key,
      on_close : (-> Nil)? = nil
    )
      @on_close       = on_close
      @packet_chan    = Channel(Bytes).new(512)
      @response_ring  = ResponseRing.new
      @wake_chan      = Channel(Nil).new(1)
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

    def shutdown
      @goaway_pending = true
      select
      when @packet_chan.send(Bytes.empty)
      else
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
          # Forward after the full drain so stream buffers accumulate across
          # the whole packet batch — reduces channel sends from O(packets) to
          # O(MB / 64KB) ≈ 16 sends for 1MB instead of ~680.
          forward_stream_data
          # Clean up fully-done streams AFTER forward_stream_data so the actor
          # maps are purged first, then the QUIC stream table is pruned.
          @quic_conn.cleanup_done_streams
          # Send ACKs / stream data immediately before yielding — keeps the
          # congestion-control feedback loop tight for throughput.
          flush_outgoing
          # Yield so handler fibers (waiting on data_chan) can run promptly.
          Fiber.yield
          # Pick up responses that handler fibers pushed during the yield.
          drain_responses

        when @wake_chan.receive
          # A handler fiber pushed a response to response_ring and sent this
          # wake signal so we don't stay blocked in select until the next packet.
          drain_responses

        when timeout(next_tick_timeout)
          @quic_conn.tick
          flush_outgoing
        end
        break if @quic_conn.closed?
      end
    rescue e
      Log.error(exception: e) { "Actor #{@initial_key[0, 8]} crashed: #{e.class}" }
    ensure
      @on_close.try &.call
      Metrics.conn_close
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
      if data.empty?
        if @goaway_pending
          # RFC 9114 §5.2 graceful drain: send GOAWAY before closing so the peer
          # can retry requests with IDs above the last-processed stream.
          last_bidi = @handled_streams.select { |sid| sid % 4 == 0 }.max? || 0_u64
          @h3_conn.send_goaway(last_bidi)
          flush_outgoing
          @quic_conn.close(0_u64, "server shutdown")
          @goaway_pending = false
        end
        return
      end
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
    end

    # Called by external fibers to submit a completed response without blocking.
    # Pushes to the lock-free ring buffer and sends a non-blocking wake signal.
    def push_response(stream_id : UInt64, data : Bytes)
      unless @response_ring.push(stream_id, data)
        Log.warn { "Actor #{@initial_key[0, 8]}: response_ring full, dropping response for stream #{stream_id}" }
      end
      # Non-blocking: capacity-1 channel; if already signalled the actor will
      # still drain the ring on its next wake.
      select
      when @wake_chan.send(nil)
      else
      end
    end

    # Drain all pending responses from the ring buffer and flush once.
    # Batching all stream writes before flushing lets the send path pack
    # multiple stream frames into fewer packets.
    private def drain_responses
      found = false
      while entry = @response_ring.pop
        stream_id, data = entry
        if stream = @quic_conn.streams[stream_id]?
          stream.write(data)
          stream.close_local
        end
        found = true
      end
      flush_outgoing if found
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

        unless @stream_eof_sent.includes?(stream_id)
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

        # Streams fully done at QUIC level won't appear in future iterations
        # (connection.cr removes them). Clean up actor-side maps now so that
        # @stream_channels and @stream_eof_sent don't accumulate indefinitely.
        if stream.fully_done?
          @stream_channels.delete(stream_id)
          @handled_streams.delete(stream_id)
          @stream_eof_sent.delete(stream_id)
        end
      end
    end

    private def dispatch_new_streams
      @quic_conn.streams.each do |stream_id, _|
        next if @handled_streams.includes?(stream_id)

        if stream_id % 4 == 0
          # Client-initiated bidirectional: HTTP/3 request
          @handled_streams << stream_id
          Metrics.request
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

    # Computes when the actor's timer should next fire.
    # Uses loss_time / PTO from the connection when available, with a 3ms minimum
    # floor to allow asyncio ACK batches to arrive before loss detection runs.
    # Falls back to 50ms when idle (no in-flight packets).
    private def next_tick_timeout : Time::Span
      if t = @quic_conn.next_event_time
        delta = t - Time.local
        return 3.milliseconds if delta <= 3.milliseconds
        [delta, 50.milliseconds].min
      else
        50.milliseconds
      end
    end

    private def flush_outgoing
      now = Time.instant
      rate = @quic_conn.pacing_rate_bps
      rate = 312_500_000.0 if rate < 312_500_000.0 # Floor pacing rate to 2.5 Gbps to prevent startup throttling
      elapsed = (now - @pacing_refill_at).total_seconds
      @pacing_refill_at = now

      # Refill token bucket; cap at 50ms worth of data.  Using 10ms caused
      # ~38% throughput loss when ACKs arrive every 26ms (quic-go ACK delay).
      max_burst = rate * 0.050
      @pacing_tokens = (@pacing_tokens + rate * elapsed).clamp(0.0, max_burst)

      # Drain all ready packets into the batch sender, then flush once with
      # sendmmsg — collapses N syscalls (one per packet) into 1-2 syscalls.
      loop do
        break if @pacing_tokens <= 0
        n = @quic_conn.send_coalesced(@out_buf)
        break if n == 0
        @batch_sender.add(@out_buf[0, n], @peer_addr)
        @pacing_tokens -= n
      end
      @batch_sender.flush
    rescue e
      Log.debug { "flush_outgoing error (peer=#{@peer_addr}): #{e.message}" }
    end

    private def init_h3_control_streams
      ctrl = @h3_conn.open_control_stream
      sf   = H3::SettingsFrame.new
      # 0x01 = QPACK_MAX_TABLE_CAPACITY: our decoder can handle up to 4096 bytes of dynamic table.
      # 0x07 = QPACK_BLOCKED_STREAMS = 16 (allow up to 16 blocked streams while waiting for encoder stream)
      # 0x06 = MAX_FIELD_SECTION_SIZE
      sf.settings = {0x01_u64 => 4096_u64, 0x07_u64 => 16_u64, 0x06_u64 => 16384_u64}
      @h3_conn.write_frame(ctrl, sf)
      @h3_conn.open_qpack_streams
      # Echo QUIC datagrams back to the sender (RFC 9221).
      # The actor's run loop calls flush_outgoing after recv_packet, so the
      # queued datagram is sent in the same batch as the ACK for the incoming packet.
      @quic_conn.on_datagram = ->(data : Bytes) {
        @quic_conn.send_datagram(data)
      }
      flush_outgoing
    rescue e
      Log.error(exception: e) { "H3 control stream init failed: #{e.class} — #{e.message}" }
    end
  end
end
