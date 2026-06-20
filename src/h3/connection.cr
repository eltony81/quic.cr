module H3
  class Connection
    getter quic : QUIC::Connection
    @control_stream_local : UInt64?
    @control_stream_remote : UInt64?
    
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

    def write_frame(stream : IO, frame : Frame)
      frame.encode(stream)
    end

    def read_frame(stream : IO) : Frame
      Frame.decode(stream)
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
