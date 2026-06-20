module QUIC
  class StreamSocket < IO
    @connection : Connection
    getter stream_id : UInt64

    def initialize(@connection, @stream_id)
    end

    def read(slice : Bytes) : Int32
      @connection.stream_read(@stream_id, slice)
    end

    def write(slice : Bytes) : Nil
      @connection.stream_write(@stream_id, slice)
    end

    def flush
      # Connection handles its own send loop
    end

    def close
      close_local
    end

    def close_local
      if stream = @connection.streams[@stream_id]?
        stream.close_local
      end
    end
  end
end
