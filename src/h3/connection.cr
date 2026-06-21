module H3
  class Connection
    getter quic : QUIC::Connection
    @control_stream_local : UInt64?
    @control_stream_remote : UInt64?
    @encoder_stream_local : QUIC::StreamSocket?
    @decoder_stream_local : QUIC::StreamSocket?

    # Persistent QPACK encoder/decoder — shared across all header frames on
    # this connection so the dynamic table accumulates compression state.
    @qpack_encoder = QPACK::Encoder.new
    @qpack_decoder = QPACK::Decoder.new

    @next_client_bidi : UInt64 = 0
    @next_client_uni : UInt64 = 2
    @next_server_bidi : UInt64 = 1
    @next_server_uni : UInt64 = 3

    def initialize(@quic)
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

    # Opens the QPACK encoder stream (type=2) and decoder stream (type=3).
    # Must be called once the QUIC handshake is complete.
    def open_qpack_streams
      return if @encoder_stream_local
      @encoder_stream_local = open_uni_stream(0x02_u64)
      @decoder_stream_local = open_uni_stream(0x03_u64)
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

    def read_frame(stream : IO) : Frame
      Frame.decode(stream, @qpack_decoder)
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

    private def generate_stream_id(bidirectional : Bool) : UInt64
      if @quic.is_server?
        if bidirectional
          id = @next_server_bidi
          @next_server_bidi += 4
          id
        else
          id = @next_server_uni
          @next_server_uni += 4
          id
        end
      else
        if bidirectional
          id = @next_client_bidi
          @next_client_bidi += 4
          id
        else
          id = @next_client_uni
          @next_client_uni += 4
          id
        end
      end
    end
  end
end
