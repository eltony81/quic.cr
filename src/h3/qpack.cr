require "./qpack/integer"
require "./qpack/huffman"
require "./qpack/static_table"
require "./qpack/dynamic_table"

module H3
  module QPACK
    # Raised by Decoder#decode when the header block references dynamic table entries
    # that have not yet been received from the peer's encoder stream (RFC 9204 §2.1.1).
    class QpackBlockedError < Exception
      getter required_insert_count : UInt64
      def initialize(@required_insert_count : UInt64)
        super("QPACK blocked: need #{required_insert_count} dynamic table insertions")
      end
    end

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

      # Encodes a set of headers into a QPACK field section (RFC 9204 Section 4.5).
      #
      # Two-pass design: first insert all novel headers into the dynamic table,
      # then encode the header block using the final insert_count as the base.
      # This ensures relative indices are correct even when multiple novel headers
      # appear in the same call.
      def encode(headers : Hash(String, String)) : Bytes
        # ----- Pass 1: insert novel headers into the dynamic table -----
        headers.each do |k, v|
          next if find_static_exact(k, v)
          next if @dynamic_table.entries.any? { |e| e.name == k && e.value == v }
          next if @dynamic_table.capacity == 0

          static_name_idx, dyn_name_idx = find_name_match(k)

          if s_idx = static_name_idx
            Integer.encode(@encoder_stream_io, s_idx.to_u64, 6, 0xC0_u8)
            encode_string(@encoder_stream_io, v, 7)
          elsif d_idx = dyn_name_idx
            Integer.encode(@encoder_stream_io, d_idx.to_u64, 6, 0x80_u8)
            encode_string(@encoder_stream_io, v, 7)
          else
            encode_string(@encoder_stream_io, k, 5, 0x40_u8)
            encode_string(@encoder_stream_io, v, 7)
          end
          @dynamic_table.add(k, v)
        end

        # Final insert count after all insertions — used as the header block base.
        final_ic = @dynamic_table.insert_count

        # ----- Pass 2: build the header block -----
        fields_io = IO::Memory.new

        headers.each do |k, v|
          if s_idx = find_static_exact(k, v)
            # Indexed Field Line – Static
            Integer.encode(fields_io, s_idx.to_u64, 6, 0xC0_u8)
          elsif d_idx = find_dynamic_exact(k, v)
            # Indexed Field Line – Dynamic
            # d_idx is the deque position; absolute index = dropped_count + d_idx
            abs_idx = @dynamic_table.dropped_count + d_idx.to_u64
            rel_idx = final_ic - 1 - abs_idx
            Integer.encode(fields_io, rel_idx, 6, 0x80_u8)
          else
            # Literal (capacity was 0, so we couldn't insert)
            _, static_name_idx_for_lit = find_name_match(k)
            dyn_name_for_lit, _ = find_name_match_dyn(k)
            if s_idx = find_static_name_only(k)
              Integer.encode(fields_io, s_idx.to_u64, 4, 0x50_u8)
              encode_string(fields_io, v, 7)
            else
              encode_string(fields_io, k, 3, 0x20_u8)
              encode_string(fields_io, v, 7)
            end
          end
        end

        # Header block prefix: RIC + Base (RFC 9204 Section 4.5.1)
        # RIC = 0 means no dynamic references; RIC = final_ic means all are pre-base.
        # Base Delta = 0 (Base == RIC), Sign = 0.
        prefix_io = IO::Memory.new
        ric = final_ic % 256
        Integer.encode(prefix_io, ric.to_u64, 8, 0x00_u8)
        prefix_io.write_byte 0x00_u8

        result = IO::Memory.new
        result.write prefix_io.to_slice
        result.write fields_io.to_slice
        result.to_slice
      end

      private def find_static_exact(k : String, v : String) : Int32?
        STATIC_TABLE.each_with_index do |entry, idx|
          return idx if entry[0] == k && entry[1] == v
        end
        nil
      end

      private def find_dynamic_exact(k : String, v : String) : Int32?
        @dynamic_table.entries.each_with_index do |entry, idx|
          return idx if entry.name == k && entry.value == v
        end
        nil
      end

      # Returns {static_idx, dynamic_idx} for name-only matches (nil if no match).
      private def find_name_match(k : String) : {Int32?, Int32?}
        s_idx = nil
        STATIC_TABLE.each_with_index do |entry, idx|
          if entry[0] == k
            s_idx = idx
            break
          end
        end
        d_idx = nil
        @dynamic_table.entries.each_with_index do |entry, idx|
          if entry.name == k
            d_idx = idx
            break
          end
        end
        {s_idx, d_idx}
      end

      private def find_name_match_dyn(k : String) : {Int32?, Nil}
        @dynamic_table.entries.each_with_index do |entry, idx|
          return {idx, nil} if entry.name == k
        end
        {nil, nil}
      end

      private def find_static_name_only(k : String) : Int32?
        STATIC_TABLE.each_with_index do |entry, idx|
          return idx if entry[0] == k
        end
        nil
      end

      private def encode_string(io : IO, str : String, prefix_len : Int32, flags : UInt8 = 0_u8)
        Integer.encode(io, str.bytesize.to_u64, prefix_len, flags)
        io.write str.to_slice
      end
    end

    class Decoder
      getter dynamic_table = DynamicTable.new
      getter last_required_insert_count : UInt64 = 0

      # Signalled whenever the dynamic table grows (via process_encoder_stream).
      # Blocked streams wait on this channel then retry decode.
      getter table_updated = Channel(Nil).new(32)

      # Processes instructions arriving on the peer's QPACK encoder stream.
      # Updates our dynamic table and unblocks any streams waiting on it.
      def process_encoder_stream(data : Bytes)
        prev = @dynamic_table.insert_count
        InstructionDecoder.new(@dynamic_table).decode(IO::Memory.new(data))
        added = @dynamic_table.insert_count - prev
        added.times do
          select
          when @table_updated.send(nil)
          else
          end
        end
      end

      def decode(bytes : Bytes) : Hash(String, String)
        headers = {} of String => String
        io = IO::Memory.new(bytes)
        return headers if io.size == 0

        # 1. Read Required Insert Count (RIC)
        first = io.read_byte || return headers
        ric = Integer.decode(io, first, 8)
        @last_required_insert_count = ric.to_u64

        # Block if the dynamic table hasn't received enough entries yet (RFC 9204 §2.1.1)
        if ric > 0 && ric.to_u64 > @dynamic_table.insert_count
          raise QpackBlockedError.new(ric.to_u64)
        end

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
