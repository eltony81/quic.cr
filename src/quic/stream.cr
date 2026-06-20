module QUIC
  enum StreamState
    Idle
    Open
    HalfClosedLocal
    HalfClosedRemote
    Closed
    Reset
  end

  class Stream
    getter id : UInt64
    getter state : StreamState = StreamState::Idle
    
    @send_buffer = IO::Memory.new
    @recv_buffer = IO::Memory.new
    
    @send_read_pos : Int64 = 0
    @recv_read_pos : Int64 = 0
    
    getter max_stream_data_remote : UInt64
    getter max_stream_data_local : UInt64
    
    @rx_offset : UInt64 = 0
    @tx_offset : UInt64 = 0
    
    def initialize(@id, @max_stream_data_remote, @max_stream_data_local)
    end

    def write(data : Bytes) : Int32
      return 0 if @state == StreamState::Closed || @state == StreamState::HalfClosedLocal
      @state = StreamState::Open if @state == StreamState::Idle
      
      allowed = @max_stream_data_remote - @tx_offset
      to_write = Math.min(data.size.to_u64, allowed).to_i
      
      return 0 if to_write <= 0
      
      @send_buffer.seek(0, IO::Seek::End)
      @send_buffer.write(data[0, to_write])
      to_write
    end

    def read(data : Bytes) : Int32
      return 0 if @recv_read_pos >= @recv_buffer.size
      
      remaining = @recv_buffer.size - @recv_read_pos
      len = Math.min(data.size.to_i64, remaining).to_i
      
      @recv_buffer.to_slice[@recv_read_pos, len].copy_to(data)
      @recv_read_pos += len
      len
    end

    def receive_data(offset : UInt64, data : Bytes)
      @state = StreamState::Open if @state == StreamState::Idle
      return if @state == StreamState::Closed || @state == StreamState::HalfClosedRemote

      if offset + data.size > @max_stream_data_local
        raise ProtocolViolation.new("Flow control limit exceeded (offset: #{offset}, data_size: #{data.size}, max_local: #{@max_stream_data_local})")

      end
      
      if offset == @rx_offset
        @recv_buffer.seek(0, IO::Seek::End)
        @recv_buffer.write(data)
        @rx_offset += data.size
      end
    end

    def update_max_stream_data(max : UInt64)
      @max_stream_data_remote = max if max > @max_stream_data_remote
    end

    def update_max_stream_data_local(max : UInt64)
      @max_stream_data_local = max if max > @max_stream_data_local
    end

    def close_local
      if @state == StreamState::Open
        @state = StreamState::HalfClosedLocal
      elsif @state == StreamState::HalfClosedRemote
        @state = StreamState::Closed
      end
    end

    def close_remote
      if @state == StreamState::Open
        @state = StreamState::HalfClosedRemote
      elsif @state == StreamState::HalfClosedLocal
        @state = StreamState::Closed
      end
    end

    @fin_sent : Bool = false

    def poll_send_data(max_len : Int32, conn_available : UInt64) : {UInt64, Bytes, Bool, Symbol?}
      return {0_u64, Bytes.empty, false, nil} if @send_read_pos >= @send_buffer.size && (!should_send_fin? || @fin_sent)
      
      offset = @tx_offset
      start_pos = @send_read_pos
      
      remaining = @send_buffer.size - start_pos
      stream_available = @max_stream_data_remote > @tx_offset ? @max_stream_data_remote - @tx_offset : 0_u64
      
      allowed = Math.min(stream_available, conn_available)
      len = Math.min(Math.min(max_len.to_i64, remaining.to_i64), allowed.to_i64).to_i
      
      blocked_reason = nil
      if remaining > 0 && len < remaining
        if stream_available == 0_u64
          blocked_reason = :stream
        elsif conn_available == 0_u64
          blocked_reason = :connection
        end
      end
      
      data = @send_buffer.to_slice[start_pos, len]
      
      @send_read_pos += len
      @tx_offset += len
      
      send_fin = false
      if should_send_fin? && @send_read_pos >= @send_buffer.size && !@fin_sent
        send_fin = true
        @fin_sent = true
      end
      
      {offset, data, send_fin, blocked_reason}
    end
    
    private def should_send_fin? : Bool
      @state == StreamState::HalfClosedLocal || @state == StreamState::Closed
    end
    
    def has_send_data? : Bool
      (@send_read_pos < @send_buffer.size) || (should_send_fin? && !@fin_sent)
    end
  end
end
