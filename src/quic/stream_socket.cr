module QUIC
  class StreamSocket < IO
    @connection : Connection
    getter stream_id : UInt64

    def initialize(@connection, @stream_id)
    end

    def read(slice : Bytes) : Int32
      loop do
        bytes_read = @connection.stream_read(@stream_id, slice)
        return bytes_read if bytes_read > 0
        
        # Check stream state
        if stream = @connection.streams[@stream_id]?
          if stream.state == StreamState::Closed || stream.state == StreamState::HalfClosedRemote
            return 0
          end
        else
          return 0
        end
        
        # Block waiting for stream updates (non-busy waiting)
        chan = @connection.stream_chans[@stream_id] ||= Channel(Bool).new(5)
        select
        when chan.receive
        when timeout(100.milliseconds)
        end
      end
    end

    def write(slice : Bytes) : Nil
      written = 0
      while written < slice.size
        n = @connection.stream_write(@stream_id, slice[written..])
        break if n == 0 # flow-control blocked; caller must pump and retry
        written += n
      end
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
