module H3
  class Connection
    getter quic : QUIC::Connection
    @control_stream_local : UInt64?
    @control_stream_remote : UInt64?
    @control_stream_socket : QUIC::StreamSocket?
    @encoder_stream_local : QUIC::StreamSocket?
    @decoder_stream_local : QUIC::StreamSocket?

    # GOAWAY tracking: the last stream ID we will process (nil = not sent).
    getter peer_goaway_stream_id : UInt64?
    property peer_goaway_stream_id : UInt64?

    # Persistent QPACK encoder/decoder — shared across all header frames on
    # this connection so the dynamic table accumulates compression state.
    @qpack_encoder = QPACK::Encoder.new
    @qpack_decoder = QPACK::Decoder.new

    @next_client_bidi : UInt64 = 0
    @next_client_uni : UInt64 = 2
    @next_server_bidi : UInt64 = 1
    @next_server_uni : UInt64 = 3

    # Guards concurrent writes to the decoder stream (Section Ack + ICI).
    @decoder_stream_mutex = Mutex.new
    # Tracks how many dynamic table entries we have already acknowledged.
    @last_acked_insert_count : UInt64 = 0

    # H3 Datagram callback (RFC 9297): called with (stream_id, payload) for
    # each incoming QUIC DATAGRAM that carries an H3 Quarter Stream ID prefix.
    property on_h3_datagram : Proc(UInt64, Bytes, Nil)?

    def initialize(@quic)
      @quic.on_datagram = ->(raw : Bytes) {
        io = IO::Memory.new(raw)
        begin
          qsi = QUIC::VarInt.decode(io)
          stream_id = qsi * 4
          rest = raw[io.pos..]
          @on_h3_datagram.try &.call(stream_id, rest)
        rescue
        end
      }
    end

    def open_request_stream : QUIC::StreamSocket
      stream_id = generate_stream_id(bidirectional: true)
      QUIC::StreamSocket.new(@quic, stream_id)
    end

    def open_uni_stream(type : UInt64) : QUIC::StreamSocket
      stream_id = generate_stream_id(bidirectional: false)
      socket = QUIC::StreamSocket.new(@quic, stream_id)
      QUIC::VarInt.write(socket, type)
      socket
    end

    # Opens the H3 control stream (type=0) and returns its socket.
    # The caller must write a SETTINGS frame as the first frame (RFC 9114 §6.2.1).
    def open_control_stream : QUIC::StreamSocket
      sock = open_uni_stream(0_u64)
      @control_stream_socket = sock
      sock
    end

    # Sends a GOAWAY frame on the control stream (RFC 9114 §7.2.6).
    # `last_stream_id` is the highest client-initiated bidi stream ID we will process.
    def send_goaway(last_stream_id : UInt64)
      if sock = @control_stream_socket
        frame = GoAwayFrame.new(last_stream_id)
        buf = IO::Memory.new
        frame.encode(buf)
        sock.write(buf.to_slice)
      end
    end

    # Sends an H3 Datagram (RFC 9297) with the given stream_id context.
    # Prepends the Quarter Stream ID (stream_id / 4) as a VarInt.
    def send_h3_datagram(stream_id : UInt64, data : Bytes)
      payload = IO::Memory.new
      QUIC::VarInt.write(payload, stream_id / 4)
      payload.write(data)
      @quic.send_datagram(payload.to_slice)
    end

    # Opens the QPACK encoder stream (type=2) and decoder stream (type=3).
    # Enables the dynamic table (capacity=4096) on our encoder and informs the
    # peer's decoder via a Set Dynamic Table Capacity instruction (RFC 9204 §3.2.2).
    #
    # To revert to static-only QPACK (no dynamic table, ~10-42% higher latency):
    #   1. In connection_actor.cr init_h3_control_streams, change SETTINGS 0x01 back to 0_u64.
    #   2. Replace the set_capacity call below with:
    #      QPACK::Integer.encode(@qpack_encoder.encoder_stream_io, 4096_u64, 5, 0x20_u8)
    #      (tells the peer its decoder may use up to 4096 bytes, but our encoder stays at cap=0)
    def open_qpack_streams
      return if @encoder_stream_local
      @encoder_stream_local = open_uni_stream(0x02_u64)
      @decoder_stream_local = open_uni_stream(0x03_u64)
      @qpack_encoder.set_capacity(4096_u64)
      flush_encoder_stream
    end

    # Processes QPACK encoder stream data arriving from the peer.
    # Updates our dynamic table and unblocks any streams waiting on it.
    def process_encoder_stream(data : Bytes)
      prev = @qpack_decoder.dynamic_table.insert_count
      @qpack_decoder.process_encoder_stream(data)
      added = @qpack_decoder.dynamic_table.insert_count - prev
      # Send Insert Count Increment to let the peer's encoder know entries arrived.
      if added > 0
        send_insert_count_increment(added)
      end
    end

    def write_frame(stream : IO, frame : Frame)
      if frame.is_a?(HeadersFrame)
        payload = @qpack_encoder.encode(frame.headers)
        # Flush any new encoder stream instructions to the peer's decoder
        flush_encoder_stream
        QUIC::VarInt.write(stream, H3::FrameType::HEADERS.to_u64)
        QUIC::VarInt.write(stream, payload.size.to_u64)
        stream.write(payload)
      else
        frame.encode(stream)
      end
    end

    # Reads and decodes the next H3 frame from the stream.
    # If a HEADERS frame references dynamic table entries not yet received,
    # blocks until the peer's encoder stream delivers them (RFC 9204 §2.1.1).
    # After successfully decoding a HEADERS frame with dynamic refs, sends a
    # Section Acknowledgment on the decoder stream (RFC 9204 §4.4.1).
    def read_frame(stream : IO) : Frame
      sid = stream.is_a?(QUIC::StreamSocket) ? stream.stream_id : nil
      frame = Frame.decode(stream, @qpack_decoder)

      # Unblock if the dynamic table hasn't caught up yet
      while frame.is_a?(BlockedHeadersFrame)
        blocked = frame
        select
        when @qpack_decoder.table_updated.receive
        when timeout(5.seconds)
          raise "QPACK blocked stream timed out waiting for encoder stream entries"
        end
        begin
          headers = @qpack_decoder.decode(blocked.raw_payload)
          frame = HeadersFrame.new(headers)
        rescue QPACK::QpackBlockedError
          # Still not enough entries; keep waiting
        end
      end

      # Send Section Acknowledgment when dynamic table references were used
      if frame.is_a?(HeadersFrame) && (s = sid) && @qpack_decoder.last_required_insert_count > 0
        send_section_ack(s)
      end

      frame
    end

    private def flush_encoder_stream
      enc_io = @qpack_encoder.encoder_stream_io
      return if enc_io.pos == 0
      if sock = @encoder_stream_local
        instructions = enc_io.to_slice.dup
        sock.write(instructions)
      end
      # Reset the buffer for the next batch of instructions
      enc_io.clear
      enc_io.rewind
    end

    # Section Acknowledgment (RFC 9204 §4.4.1): 1XXXXXXX stream_id (7-bit prefix)
    private def send_section_ack(stream_id : UInt64)
      write_decoder_instruction do |io|
        QPACK::Integer.encode(io, stream_id, 7, 0x80_u8)
        @last_acked_insert_count = @qpack_decoder.dynamic_table.insert_count
      end
    end

    # Insert Count Increment (RFC 9204 §4.4.3): 00XXXXXX count (6-bit prefix)
    private def send_insert_count_increment(count : UInt64)
      write_decoder_instruction do |io|
        QPACK::Integer.encode(io, count, 6, 0x00_u8)
      end
    end

    private def write_decoder_instruction(&block : IO ->)
      return unless sock = @decoder_stream_local
      @decoder_stream_mutex.synchronize do
        buf = IO::Memory.new
        block.call(buf)
        sock.write(buf.to_slice)
      end
    end

    private def generate_stream_id(bidirectional : Bool) : UInt64
      if @quic.is_server?
        if bidirectional
          check_stream_limit(@next_server_bidi, @quic.max_streams_bidi_remote, "bidi")
          id = @next_server_bidi
          @next_server_bidi += 4
          id
        else
          check_stream_limit(@next_server_uni, @quic.max_streams_uni_remote, "uni")
          id = @next_server_uni
          @next_server_uni += 4
          id
        end
      else
        if bidirectional
          check_stream_limit(@next_client_bidi, @quic.max_streams_bidi_remote, "bidi")
          id = @next_client_bidi
          @next_client_bidi += 4
          id
        else
          check_stream_limit(@next_client_uni, @quic.max_streams_uni_remote, "uni")
          id = @next_client_uni
          @next_client_uni += 4
          id
        end
      end
    end

    # RFC 9000 §4.6: raise if the peer's stream limit would be exceeded.
    # `next_id` is the next stream ID we would use; divide by 4 to get the
    # ordinal (stream IDs are 4k+offset).  A limit of 0 means "not yet known"
    # (transport params not applied) — allow opening freely in that case.
    private def check_stream_limit(next_id : UInt64, limit : UInt64, kind : String)
      return if limit == 0
      ordinal = next_id / 4
      if ordinal >= limit
        raise QUIC::ProtocolViolation.new(
          "#{kind} stream limit exceeded (limit=#{limit}, ordinal=#{ordinal})"
        )
      end
    end
  end
end
