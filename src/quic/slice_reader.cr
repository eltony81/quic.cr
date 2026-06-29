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

    def read_byte : UInt8?
      return nil if @pos >= @slice.size
      byte = @slice[@pos]
      @pos += 1
      byte
    end

    def read_varint : UInt64
      raise BufferTooShort.new if @pos >= @slice.size
      first_byte = @slice[@pos]
      @pos += 1
      len_type = first_byte >> 6
      
      case len_type
      when 0
        (first_byte & 0x3f).to_u64
      when 1
        raise BufferTooShort.new if @pos >= @slice.size
        second_byte = @slice[@pos]
        @pos += 1
        ((first_byte.to_u64 & 0x3f) << 8) | second_byte.to_u64
      when 2
        raise BufferTooShort.new if @pos + 3 > @slice.size
        b0 = @slice[@pos].to_u64
        b1 = @slice[@pos + 1].to_u64
        b2 = @slice[@pos + 2].to_u64
        @pos += 3
        ((first_byte.to_u64 & 0x3f) << 24) | (b0 << 16) | (b1 << 8) | b2
      when 3
        raise BufferTooShort.new if @pos + 7 > @slice.size
        b0 = @slice[@pos].to_u64
        b1 = @slice[@pos + 1].to_u64
        b2 = @slice[@pos + 2].to_u64
        b3 = @slice[@pos + 3].to_u64
        b4 = @slice[@pos + 4].to_u64
        b5 = @slice[@pos + 5].to_u64
        b6 = @slice[@pos + 6].to_u64
        @pos += 7
        ((first_byte.to_u64 & 0x3f) << 56) | (b0 << 48) | (b1 << 40) | (b2 << 32) | (b3 << 24) | (b4 << 16) | (b5 << 8) | b6
      else
        raise InternalError.new("Unreachable VarInt length type")
      end
    end

    def skip(n : Int32 | Int64 | UInt64) : Nil
      advance = Math.min(n.to_i, @slice.size - @pos)
      @pos += advance if advance > 0
    end

    def write(slice : Bytes) : Nil
      raise IO::Error.new("SliceReader is read-only")
    end
  end
end
