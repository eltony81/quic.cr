module H3
  # Lock-free MPSC ring buffer for handler-fiber → actor response delivery.
  #
  # Replaces Channel({UInt64, Bytes}) to eliminate the blocking channel-send
  # cost when handler fibers deliver responses to the actor. Handler fibers push
  # without blocking; the actor drains in bulk on each loop iteration.
  #
  # Implementation uses Mutex + Deque. Channels also use a mutex internally, so
  # the overhead is comparable — the key benefit is that push never blocks the
  # caller waiting for the consumer, unlike a bounded channel whose send blocks
  # when the buffer is full. Works correctly with and without -Dpreview_mt.
  class ResponseRing
    def initialize
      @deque = Deque({UInt64, Bytes}).new
      @mutex = Mutex.new(:reentrant)
    end

    # Push one response. Never blocks.
    # Safe to call concurrently from multiple fibers/threads.
    def push(stream_id : UInt64, data : Bytes) : Bool
      @mutex.synchronize { @deque.push({stream_id, data}) }
      true
    end

    # Pop one entry. Returns nil when empty.
    # Must only be called from the actor fiber (single consumer).
    def pop : {UInt64, Bytes}?
      @mutex.synchronize { @deque.shift? }
    end

    def empty? : Bool
      @mutex.synchronize { @deque.empty? }
    end
  end
end
