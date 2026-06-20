require "./qpack/integer"
require "./qpack/huffman"
require "./qpack/static_table"
require "./qpack/dynamic_table"

module H3
  module QPACK
    def self.decode_string(io : IO, n : Int32, first_byte : UInt8? = nil) : String
      b = first_byte || io.read_byte || return ""
      h_mask = (1_u8 << n)
      is_huffman = (b & h_mask) != 0
      len = Integer.decode(io, b, n)
      
      if len > io.size - io.pos
        len = (io.size - io.pos).to_u64
      end
      buf = Bytes.new(len)
      io.read_fully(buf)
      
      is_huffman ? Huffman.decode(buf) : String.new(buf)
    end

    class InstructionDecoder
      def initialize(@dynamic_table : DynamicTable)
      end
      
      def decode(io : IO)
        while io.pos < io.size
          b = io.read_byte || break
          
          if (b & 0xE0) == 0x20
            # 001 XXXXX (Set Dynamic Table Capacity)
            capacity = Integer.decode(io, b, 5).to_u64
            @dynamic_table.set_capacity(capacity)
            
          elsif (b & 0x80) == 0x80
            # 1 T XXXXXX (Insert With Name Reference)
            is_static = (b & 0x40) != 0
            idx = Integer.decode(io, b, 6).to_i
            entry = is_static ? STATIC_TABLE[idx]? : @dynamic_table.get_by_absolute(idx.to_u64)
            name = entry ? entry[0] : ""
            value = H3::QPACK.decode_string(io, 7)
            @dynamic_table.add(name, value)
            
          elsif (b & 0xC0) == 0x40
            # 01 H XXXXX (Insert Without Name Reference)
            name = H3::QPACK.decode_string(io, 5, b)
            value = H3::QPACK.decode_string(io, 7)
            @dynamic_table.add(name, value)
            
          elsif (b & 0xE0) == 0x00
            # 000 XXXXX (Duplicate)
            idx = Integer.decode(io, b, 5).to_i
            if entry = @dynamic_table.get_by_absolute(idx.to_u64)
              @dynamic_table.add(entry[0], entry[1])
            end
          else
            break
          end
        end
      end
    end

    class Encoder
      getter dynamic_table = DynamicTable.new
      getter encoder_stream_io = IO::Memory.new

      def encode(headers : Hash(String, String)) : Bytes
        io = IO::Memory.new
        
        # Calculate insert count
        inserted = 0
        
        headers.each do |k, v|
          exact_match_idx = nil
          name_match_idx = nil
          is_static_exact = false
          is_static_name = false
          
          # Search Dynamic Table
          @dynamic_table.entries.each_with_index do |entry, idx|
            if entry.name == k
              name_match_idx = idx unless name_match_idx
              if entry.value == v
                exact_match_idx = idx
                break
              end
            end
          end
          
          # Search Static Table (only if no exact match in dynamic table)
          if !exact_match_idx
            STATIC_TABLE.each_with_index do |entry, idx|
              if entry[0] == k
                if !name_match_idx
                  name_match_idx = idx
                  is_static_name = true
                end
                if entry[1] == v
                  exact_match_idx = idx
                  is_static_exact = true
                  break
                end
              end
            end
          end
          
          if idx = exact_match_idx
            if is_static_exact
              # Indexed Field Line - Static
              Integer.encode(io, idx.to_u64, 6, 0xC0_u8)
            else
              # Indexed Field Line - Dynamic (Relative Index)
              # For simplicity, base == insert_count, so relative = Base - 1 - Absolute = @insert_count - 1 - (@dropped_count + idx)
              abs_idx = @dynamic_table.dropped_count + idx.to_u64
              rel_idx = @dynamic_table.insert_count - 1 - abs_idx
              Integer.encode(io, rel_idx, 6, 0x80_u8)
            end
          else
            # No exact match. Let's insert it into the dynamic table to save space later!
            if @dynamic_table.capacity > 0
              if idx = name_match_idx
                # Insert With Name Reference
                is_static = is_static_name
                flags = is_static ? 0xC0_u8 : 0x80_u8
                Integer.encode(@encoder_stream_io, idx.to_u64, 6, flags)
                encode_string(@encoder_stream_io, v, 7)
              else
                # Insert Without Name Reference
                encode_string(@encoder_stream_io, k, 5, 0x40_u8)
                encode_string(@encoder_stream_io, v, 7)
              end
              @dynamic_table.add(k, v)
              inserted += 1
              
              # Now reference the newly inserted item using Indexed Field Line
              rel_idx = 0_u64 # It's the most recent item, so relative idx = 0
              Integer.encode(io, rel_idx, 6, 0x80_u8)
            else
              # Cannot insert, use Literal Field Line
              if idx = name_match_idx
                if is_static_name
                  Integer.encode(io, idx.to_u64, 4, 0x50_u8)
                else
                  # Literal with Name Ref - Dynamic (Relative Index)
                  abs_idx = @dynamic_table.dropped_count + idx.to_u64
                  rel_idx = @dynamic_table.insert_count - 1 - abs_idx
                  Integer.encode(io, rel_idx, 4, 0x40_u8)
                end
                encode_string(io, v, 7)
              else
                # Literal Without Name Ref
                encode_string(io, k, 3, 0x20_u8)
                encode_string(io, v, 7)
              end
            end
          end
        end
        
        # Now prepend RIC and Base
        final_io = IO::Memory.new
        # RIC = @dynamic_table.insert_count (simplified max entries % 256)
        # Assuming ric fits in 8 bits for now
        ric = @dynamic_table.insert_count % 256
        Integer.encode(final_io, ric.to_u64, 8, 0x00_u8)
        # Base Delta = 0 (Base == RIC), Sign = 0
        final_io.write_byte 0x00_u8
        
        final_io.write io.to_slice
        final_io.to_slice
      end
      
      private def encode_string(io : IO, str : String, prefix_len : Int32, flags : UInt8 = 0_u8)
        # Without Huffman.encode, we send raw strings (H=0).
        Integer.encode(io, str.bytesize.to_u64, prefix_len, flags)
        io.write str.to_slice
      end
    end

    class Decoder
      getter dynamic_table = DynamicTable.new

      def decode(bytes : Bytes) : Hash(String, String)
        headers = {} of String => String
        io = IO::Memory.new(bytes)
        return headers if io.size == 0
        
        # 1. Read Required Insert Count (RIC)
        first = io.read_byte || return headers
        ric = Integer.decode(io, first, 8)
        
        # 2. Read Base
        second = io.read_byte || return headers
        base_sign = (second & 0x80) != 0
        base_delta = Integer.decode(io, second, 7)

        # Base calculation (RFC 9204 Section 4.5.1)
        base = 0_u64
        if ric > 0
          req_insert_count = ric.to_u64 # Simplified RIC mapping
          if !base_sign
            base = req_insert_count + base_delta.to_u64
          else
            base = req_insert_count - base_delta.to_u64 - 1
          end
        end

        while io.pos < io.size
          b = io.read_byte || break
          
          if (b & 0x80) == 0x80
            # 1 T XXXXXX (Indexed Field Line)
            is_static = (b & 0x40) != 0
            idx = Integer.decode(io, b, 6).to_i
            entry = is_static ? STATIC_TABLE[idx]? : @dynamic_table.get_by_relative(base, idx.to_u64)
            if entry
              headers[entry[0]] = entry[1]
            end
            
          elsif (b & 0xC0) == 0x40
            # 01 N T XXXX (Literal Field Line With Name Reference)
            is_static = (b & 0x10) != 0
            idx = Integer.decode(io, b, 4).to_i
            entry = is_static ? STATIC_TABLE[idx]? : @dynamic_table.get_by_relative(base, idx.to_u64)
            name = entry ? entry[0] : ""
            value = H3::QPACK.decode_string(io, 7)
            if !name.empty?
              headers[name] = value
            end
            
          elsif (b & 0xE0) == 0x20
            # 001 N H XXX (Literal Field Line Without Name Reference)
            # N is bit 4 (0x10)
            name = H3::QPACK.decode_string(io, 3, b)
            value = H3::QPACK.decode_string(io, 7)
            if !name.empty?
              headers[name] = value
            end
            
          elsif (b & 0xF0) == 0x10
            # 0001 XXXXX (Indexed Field Line With Post-Base Index)
            idx = Integer.decode(io, b, 4).to_i
            if entry = @dynamic_table.get_by_post_base(base, idx.to_u64)
              headers[entry[0]] = entry[1]
            end
            
          elsif (b & 0xF8) == 0x00
            # 0000 N XXX (Literal Field Line With Post-Base Name Reference)
            idx = Integer.decode(io, b, 3).to_i
            entry = @dynamic_table.get_by_post_base(base, idx.to_u64)
            name = entry ? entry[0] : ""
            value = H3::QPACK.decode_string(io, 7)
            if !name.empty?
              headers[name] = value
            end
          else
            # Unrecognized/Reserved pattern, break to avoid infinite loop
            break
          end
        end
        headers
      end
    end
  end
end
