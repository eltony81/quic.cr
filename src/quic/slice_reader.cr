module QUIC
  # A simple allocation-free IO wrapper around a Bytes slice, allowing
  # reuse across multiple parsing operations by resetting the slice reference.
  class SliceReader < IO
    @slice : Bytes
    @pos : Int32

    def initialize
      @slice = Bytes.empty
      @pos = 0
    end

    def reset(slice : Bytes) : Nil
      @slice = slice
      @pos = 0
    end

    # Return number of remaining bytes in the slice.
    def remaining : Int32
      @slice.size - @pos
    end

    # Return current position.
    def pos : Int32
      @pos
    end

    # Return size of the slice.
    def size : Int32
      @slice.size
    end

    def read(slice : Bytes) : Int32
      count = Math.min(slice.size, @slice.size - @pos)
      return 0 if count <= 0
      slice.copy_from(@slice[@pos, count])
      @pos += count
      count
    end

    def write(slice : Bytes) : Nil
      raise IO::Error.new("SliceReader is read-only")
    end
  end
end
