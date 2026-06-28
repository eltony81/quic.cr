module QUIC
  module VarInt
    # Encodes a UInt64 into a QUIC variable-length integer and writes directly to IO.
    def self.write(io : IO, value : UInt64) : Nil
      if value <= 0x3f
        io.write_byte(value.to_u8)
      elsif value <= 0x3fff
        v = value.to_u16 | 0x4000
        buf2 = uninitialized UInt8[2]
        buf2[0] = ((v >> 8) & 0xff).to_u8
        buf2[1] = (v & 0xff).to_u8
        io.write(buf2.to_slice)
      elsif value <= 0x3fffffff
        v = value.to_u64 | 0x80000000_u64
        buf4 = uninitialized UInt8[4]
        buf4[0] = ((v >> 24) & 0xff).to_u8
        buf4[1] = ((v >> 16) & 0xff).to_u8
        buf4[2] = ((v >> 8) & 0xff).to_u8
        buf4[3] = (v & 0xff).to_u8
        io.write(buf4.to_slice)
      elsif value <= 0x3fffffffffffffff_u64
        v = value | 0xc000000000000000_u64
        buf8 = uninitialized UInt8[8]
        buf8[0] = ((v >> 56) & 0xff).to_u8
        buf8[1] = ((v >> 48) & 0xff).to_u8
        buf8[2] = ((v >> 40) & 0xff).to_u8
        buf8[3] = ((v >> 32) & 0xff).to_u8
        buf8[4] = ((v >> 24) & 0xff).to_u8
        buf8[5] = ((v >> 16) & 0xff).to_u8
        buf8[6] = ((v >> 8) & 0xff).to_u8
        buf8[7] = (v & 0xff).to_u8
        io.write(buf8.to_slice)
      else
        raise Error.new("Value too large for QUIC VarInt: #{value}")
      end
    end

    # Legacy wrapper for compatibility (allocates Bytes).
    def self.encode(value : UInt64) : Bytes
      io = IO::Memory.new
      write(io, value)
      io.to_slice
    end

    # Decodes a QUIC variable-length integer from an IO without allocations.
    def self.decode(io : IO) : UInt64
      first_byte = io.read_byte || raise BufferTooShort.new
      len_type = first_byte >> 6
      
      case len_type
      when 0 # 1 byte
        (first_byte & 0x3f).to_u64
      when 1 # 2 bytes
        second_byte = io.read_byte || raise BufferTooShort.new
        ((first_byte.to_u64 & 0x3f) << 8) | second_byte.to_u64
      when 2 # 4 bytes
        res = (first_byte.to_u64 & 0x3f) << 24
        b1 = io.read_byte || raise BufferTooShort.new
        b2 = io.read_byte || raise BufferTooShort.new
        b3 = io.read_byte || raise BufferTooShort.new
        res | (b1.to_u64 << 16) | (b2.to_u64 << 8) | b3.to_u64
      when 3 # 8 bytes
        res = (first_byte.to_u64 & 0x3f) << 56
        b1 = io.read_byte || raise BufferTooShort.new
        b2 = io.read_byte || raise BufferTooShort.new
        b3 = io.read_byte || raise BufferTooShort.new
        b4 = io.read_byte || raise BufferTooShort.new
        b5 = io.read_byte || raise BufferTooShort.new
        b6 = io.read_byte || raise BufferTooShort.new
        b7 = io.read_byte || raise BufferTooShort.new
        res | (b1.to_u64 << 48) | (b2.to_u64 << 40) | (b3.to_u64 << 32) |
              (b4.to_u64 << 24) | (b5.to_u64 << 16) | (b6.to_u64 << 8) | b7.to_u64
      else
        raise InternalError.new("Unreachable VarInt length type")
      end
    end
  end
end
