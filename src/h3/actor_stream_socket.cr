module H3
  # IO adapter for the actor model. Reads stream data from a channel filled by
  # ConnectionActor; buffers writes and delivers them to the actor on close_local.
  class ActorStreamSocket < IO
    getter stream_id : UInt64

    @data_chan : Channel(Bytes)
    @actor     : ConnectionActor
    @write_buf : IO::Memory
    @leftover  : Bytes
    @eof       : Bool
    @sent      : Bool

    def initialize(@stream_id, @data_chan, @actor)
      @write_buf = IO::Memory.new(4096)
      @leftover  = Bytes.empty
      @eof       = false
      @sent      = false
    end

    def read(slice : Bytes) : Int32
      if @leftover.size > 0
        n = Math.min(slice.size, @leftover.size)
        @leftover[0, n].copy_to(slice)
        @leftover = @leftover[n..]
        return n
      end
      return 0 if @eof

      chunk = @data_chan.receive
      if chunk.empty?
        @eof = true
        return 0
      end
      n = Math.min(slice.size, chunk.size)
      chunk[0, n].copy_to(slice)
      @leftover = chunk[n..] if n < chunk.size
      n
    end

    def write(slice : Bytes) : Nil
      @write_buf.write(slice)
    end

    def flush; end

    def close
      close_local
    end

    # Idempotent: safe to call more than once.
    # Pushes to the actor's lock-free response ring — never blocks.
    def close_local
      return if @sent
      @sent = true
      @actor.push_response(@stream_id, @write_buf.to_slice.dup)
    end
  end
end
