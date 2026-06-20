module H3
  module QPACK
    class DynamicTable
      record Entry, name : String, value : String, size : Int32

      getter capacity : UInt64 = 0
      getter size : UInt64 = 0
      getter entries = Deque(Entry).new
      getter insert_count : UInt64 = 0
      getter dropped_count : UInt64 = 0

      def set_capacity(new_capacity : UInt64)
        @capacity = new_capacity
        evict_if_needed
      end

      def add(name : String, value : String)
        entry_size = name.bytesize + value.bytesize + 32
        
        # Add the new entry
        @entries.push(Entry.new(name, value, entry_size))
        @size += entry_size
        @insert_count += 1
        
        evict_if_needed
      end

      private def evict_if_needed
        while @size > @capacity && !@entries.empty?
          dropped = @entries.shift
          @size -= dropped.size
          @dropped_count += 1
        end
      end

      # Access an entry using its absolute index
      def get_by_absolute(index : UInt64) : {String, String}?
        if index >= @dropped_count && index < @insert_count
          idx = index - @dropped_count
          entry = @entries[idx]?
          return {entry.name, entry.value} if entry
        end
        nil
      end
      
      # Decoder: Relative Index
      # absolute_index = Base - 1 - relative_index
      def get_by_relative(base : UInt64, relative_index : UInt64) : {String, String}?
        return nil if base <= relative_index
        absolute_index = base - 1 - relative_index
        get_by_absolute(absolute_index)
      end
      
      # Decoder: Post-Base Index
      # absolute_index = Base + post_base_index
      def get_by_post_base(base : UInt64, post_base_index : UInt64) : {String, String}?
        absolute_index = base + post_base_index
        get_by_absolute(absolute_index)
      end
    end
  end
end
