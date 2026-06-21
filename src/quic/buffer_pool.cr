module QUIC
  # A simple fixed-size buffer pool to reduce GC pressure in the hot UDP receive
  # path. Buffers are leased for one receive cycle and returned immediately,
  # keeping allocation count near zero under steady-state load.
  class BufferPool
    DEFAULT_BUFFER_SIZE = 65536
    DEFAULT_POOL_SIZE   = 32

    def initialize(
      buffer_size : Int32 = DEFAULT_BUFFER_SIZE,
      pool_size   : Int32 = DEFAULT_POOL_SIZE
    )
      @buffer_size = buffer_size
      @pool = Array(Bytes).new(pool_size) { Bytes.new(buffer_size) }
      @mutex = Mutex.new
    end

    # Leases a buffer from the pool. Allocates a fresh one if the pool is empty.
    def lease : Bytes
      @mutex.synchronize { @pool.pop? } || Bytes.new(@buffer_size)
    end

    # Returns a previously leased buffer to the pool.
    # The caller must not retain a reference to the buffer after calling this.
    def return(buf : Bytes)
      return if buf.size != @buffer_size
      @mutex.synchronize { @pool << buf }
    end

    # Yields a leased buffer and automatically returns it after the block.
    def borrow
      buf = lease
      begin
        yield buf
      ensure
        self.return(buf)
      end
    end
  end
end
