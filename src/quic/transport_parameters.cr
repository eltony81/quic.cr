module QUIC
  # QUIC Transport Parameters (RFC 9000, Section 18)
  class TransportParameters
    property original_destination_connection_id : Bytes?
    property max_idle_timeout : UInt64 = 0
    property stateless_reset_token : Bytes?
    property max_udp_payload_size : UInt64 = 65527
    property initial_max_data : UInt64 = 0
    property initial_max_stream_data_bidi_local : UInt64 = 0
    property initial_max_stream_data_bidi_remote : UInt64 = 0
    property initial_max_stream_data_uni : UInt64 = 0
    property initial_max_streams_bidi : UInt64 = 0
    property initial_max_streams_uni : UInt64 = 0
    property ack_delay_exponent : UInt64 = 3
    property max_ack_delay : UInt64 = 25
    property disable_active_migration : Bool = false
    property preferred_address : Bytes? # Simplified for now
    property active_connection_id_limit : UInt64 = 2
    property initial_source_connection_id : Bytes?
    property retry_source_connection_id : Bytes?
    property max_datagram_frame_size : UInt64 = 0
    # RFC 9368: Compatible Version Negotiation.
    # {chosen_version, [other_supported_versions]}
    property quic_version_information : {UInt32, Array(UInt32)}? = nil

    def encode(io : IO)
      write_param(io, 0x00_u64, @original_destination_connection_id)
      write_param(io, 0x01_u64, @max_idle_timeout) if @max_idle_timeout > 0
      write_param(io, 0x02_u64, @stateless_reset_token)
      write_param(io, 0x03_u64, @max_udp_payload_size) # RFC 9000 §18.2: always advertise
      write_param(io, 0x04_u64, @initial_max_data) if @initial_max_data > 0
      write_param(io, 0x05_u64, @initial_max_stream_data_bidi_local) if @initial_max_stream_data_bidi_local > 0
      write_param(io, 0x06_u64, @initial_max_stream_data_bidi_remote) if @initial_max_stream_data_bidi_remote > 0
      write_param(io, 0x07_u64, @initial_max_stream_data_uni) if @initial_max_stream_data_uni > 0
      write_param(io, 0x08_u64, @initial_max_streams_bidi) if @initial_max_streams_bidi > 0
      write_param(io, 0x09_u64, @initial_max_streams_uni) if @initial_max_streams_uni > 0
      write_param(io, 0x0a_u64, @ack_delay_exponent) if @ack_delay_exponent != 3
      write_param(io, 0x0b_u64, @max_ack_delay) if @max_ack_delay != 25
      write_empty_param(io, 0x0c_u64) if @disable_active_migration
      write_param(io, 0x0d_u64, @preferred_address)
      write_param(io, 0x0e_u64, @active_connection_id_limit) if @active_connection_id_limit != 2
      write_param(io, 0x0f_u64, @initial_source_connection_id)
      write_param(io, 0x10_u64, @retry_source_connection_id)
      write_param(io, 0x20_u64, @max_datagram_frame_size) if @max_datagram_frame_size > 0
      if vi = @quic_version_information
        chosen, others = vi
        io.write VarInt.encode(0x11_u64)
        val_size = 4 + 4 * others.size
        io.write VarInt.encode(val_size.to_u64)
        IO::ByteFormat::NetworkEndian.encode(chosen, io)
        others.each { |v| IO::ByteFormat::NetworkEndian.encode(v, io) }
      end
    end

    private def write_param(io : IO, id : UInt64, value : UInt64)
      io.write VarInt.encode(id)
      val_bytes = VarInt.encode(value)
      io.write VarInt.encode(val_bytes.size.to_u64)
      io.write val_bytes
    end

    private def write_param(io : IO, id : UInt64, value : Bytes?)
      if val = value
        io.write VarInt.encode(id)
        io.write VarInt.encode(val.size.to_u64)
        io.write val
      end
    end

    private def write_empty_param(io : IO, id : UInt64)
      io.write VarInt.encode(id)
      io.write VarInt.encode(0_u64)
    end

    def self.decode(io : IO) : TransportParameters
      params = new
      while io.pos < io.size
        id = VarInt.decode(io)
        length = VarInt.decode(io)
        Log.trace { "Decoding transport parameter ID: 0x#{id.to_s(16)}, length: #{length}" }
        begin
          case id
          when 0x00_u64
            params.original_destination_connection_id = read_bytes(io, length)
          when 0x01_u64
            params.max_idle_timeout = read_varint_value(io, length)
          when 0x02_u64
            params.stateless_reset_token = read_bytes(io, length)
          when 0x03_u64
            params.max_udp_payload_size = read_varint_value(io, length)
          when 0x04_u64
            params.initial_max_data = read_varint_value(io, length)
          when 0x05_u64
            params.initial_max_stream_data_bidi_local = read_varint_value(io, length)
          when 0x06_u64
            params.initial_max_stream_data_bidi_remote = read_varint_value(io, length)
          when 0x07_u64
            params.initial_max_stream_data_uni = read_varint_value(io, length)
          when 0x08_u64
            params.initial_max_streams_bidi = read_varint_value(io, length)
          when 0x09_u64
            params.initial_max_streams_uni = read_varint_value(io, length)
          when 0x0a_u64
            params.ack_delay_exponent = read_varint_value(io, length)
          when 0x0b_u64
            params.max_ack_delay = read_varint_value(io, length)
          when 0x0c_u64
            params.disable_active_migration = true
            io.skip(length)
          when 0x0d_u64
            params.preferred_address = read_bytes(io, length)
          when 0x0e_u64
            params.active_connection_id_limit = read_varint_value(io, length)
          when 0x0f_u64
            params.initial_source_connection_id = read_bytes(io, length)
          when 0x10_u64
            params.retry_source_connection_id = read_bytes(io, length)
          when 0x20_u64
            params.max_datagram_frame_size = read_varint_value(io, length)
          when 0x11_u64
            # RFC 9368: Version Information TP
            chosen = IO::ByteFormat::NetworkEndian.decode(UInt32, io)
            others = [] of UInt32
            bytes_read = 4_u64
            while bytes_read + 4 <= length
              others << IO::ByteFormat::NetworkEndian.decode(UInt32, io)
              bytes_read += 4
            end
            io.skip(length - bytes_read) if bytes_read < length
            params.quic_version_information = {chosen, others}
          else
            # Ignore unknown parameters
            io.skip(length)
          end
        rescue ex
          Log.trace { "Error decoding transport parameter ID 0x#{id.to_s(16)}: #{ex.message}" }
          raise ex
        end
      end
      params
    end

    private def self.read_bytes(io : IO, length : UInt64) : Bytes
      b = Bytes.new(length)
      io.read_fully(b)
      b
    end

    private def self.read_varint_value(io : IO, length : UInt64) : UInt64
      # The value inside the parameter is itself a VarInt
      # Wait, RFC 9000 Section 18.2 says:
      # "Numeric values are encoded as variable-length integers."
      # This means the content of the parameter is a VarInt.
      # However, we must ensure we only read exactly 'length' bytes.
      start = io.pos
      val = VarInt.decode(io)
      actual_read = io.pos - start
      if actual_read < length
        io.skip(length - actual_read)
      elsif actual_read > length
        raise ProtocolViolation.new("Transport parameter length mismatch")
      end
      val
    end
  end
end
