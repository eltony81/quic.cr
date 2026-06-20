module H3
  module QPACK
    module Integer
      # Decodes an integer from the IO using an N-bit prefix.
      # The first byte is expected to have already been read, and its value
      # (masked to the N bits) is provided as `prefix_val`.
      def self.decode(io : IO, prefix_val : UInt8, n : Int32) : UInt64
        mask = case n
               when 1 then 0x01_u8
               when 2 then 0x03_u8
               when 3 then 0x07_u8
               when 4 then 0x0F_u8
               when 5 then 0x1F_u8
               when 6 then 0x3F_u8
               when 7 then 0x7F_u8
               when 8 then 0xFF_u8
               else raise "Invalid prefix length #{n}"
               end
        val = (prefix_val & mask).to_u64
        
        if val < mask
          return val
        end
        
        m = 0
        loop do
          b = io.read_byte || raise "Unexpected EOF while decoding QPACK integer"
          val += (b & 127).to_u64 << m
          m += 7
          break if (b & 128) == 0
        end
        
        val
      end

      # Encodes an integer to the IO using an N-bit prefix.
      # `first_byte` contains any flags that should be placed in the upper (8 - n) bits.
      def self.encode(io : IO, value : UInt64, n : Int32, first_byte : UInt8 = 0_u8)
        mask = (1_u64 << n) - 1_u64
        
        if value < mask
          io.write_byte(first_byte | value.to_u8)
        else
          io.write_byte(first_byte | mask.to_u8)
          value -= mask
          while value >= 128
            io.write_byte((value % 128 + 128).to_u8)
            value //= 128
          end
          io.write_byte(value.to_u8)
        end
      end
    end
  end
end
