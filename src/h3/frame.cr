module H3
  VERSION = "0.1.0"

  enum FrameType : UInt64
    DATA          = 0x00
    HEADERS       = 0x01
    CANCEL_PUSH   = 0x03
    SETTINGS      = 0x04
    PUSH_PROMISE  = 0x05
    GOAWAY        = 0x07
    MAX_PUSH_ID   = 0x0d
  end

  abstract class Frame
    abstract def type : FrameType
    abstract def encode(io : IO)
  end

  class DataFrame < Frame
    getter data : Bytes
    def initialize(@data); end
    def type : FrameType; FrameType::DATA; end
    def encode(io : IO)
      QUIC::VarInt.write(io, type.to_u64)
      QUIC::VarInt.write(io, @data.size.to_u64)
      io.write @data
    end
  end

  class SettingsFrame < Frame
    property settings = {} of UInt64 => UInt64
    def type : FrameType; FrameType::SETTINGS; end
    def encode(io : IO)
      payload = IO::Memory.new
      @settings.each do |k, v|
        QUIC::VarInt.write(payload, k)
        QUIC::VarInt.write(payload, v)
      end
      QUIC::VarInt.write(io, type.to_u64)
      QUIC::VarInt.write(io, payload.size.to_u64)
      io.write payload.to_slice
    end
  end

  class HeadersFrame < Frame
    getter headers : Hash(String, String)

    def initialize(@headers)
    end

    def type : FrameType; FrameType::HEADERS; end

    def encode(io : IO)
      payload = QPACK::Encoder.new.encode(@headers)
      QUIC::VarInt.write(io, type.to_u64)
      QUIC::VarInt.write(io, payload.size.to_u64)
      io.write payload
    end
  end

  # Received when the client sends a PUSH_PROMISE frame; clients MUST NOT send
  # PUSH_PROMISE (RFC 9114 §7.2.5), so this always triggers H3_ID_ERROR.
  class PushPromiseFrame < Frame
    def type : FrameType; FrameType::PUSH_PROMISE; end
    def encode(io : IO); end
  end

  # PRIORITY_UPDATE frame (RFC 9218). Extended frame types 0xF0700 (request)
  # and 0xF0701 (push). Parse-only; no priority enforcement is performed.
  class PriorityUpdateFrame < Frame
    getter element_id : UInt64
    getter priority_field_value : String
    getter? request : Bool

    def initialize(@element_id, @priority_field_value, @request = true); end
    def type : FrameType; FrameType::PUSH_PROMISE; end  # placeholder
    def encode(io : IO)
      type_id = @request ? 0xF0700_u64 : 0xF0701_u64
      payload = IO::Memory.new
      QUIC::VarInt.write(payload, @element_id)
      payload.write(@priority_field_value.to_slice)
      QUIC::VarInt.write(io, type_id)
      QUIC::VarInt.write(io, payload.size.to_u64)
      io.write payload.to_slice
    end
  end

  # Sent on the control stream to initiate graceful shutdown (RFC 9114 §7.2.6).
  # The payload is a single VarInt: the ID of the last request stream the sender
  # will process. Streams with IDs higher than this must be retried by the client.
  class GoAwayFrame < Frame
    getter stream_id : UInt64
    def initialize(@stream_id); end
    def type : FrameType; FrameType::GOAWAY; end
    def encode(io : IO)
      payload = IO::Memory.new
      QUIC::VarInt.write(payload, @stream_id)
      QUIC::VarInt.write(io, type.to_u64)
      QUIC::VarInt.write(io, payload.size.to_u64)
      io.write payload.to_slice
    end
  end

  # Carries an H3 frame type that this implementation does not understand.
  # RFC 9114 §9: unknown frame types MUST be ignored.
  class UnknownFrame < Frame
    getter raw_data : Bytes
    getter frame_type_id : UInt64
    def initialize(@frame_type_id, @raw_data); end
    def type : FrameType; FrameType::DATA; end  # placeholder
    def encode(io : IO); end
  end

  # Returned by Frame.decode when a HEADERS payload can't be decoded yet because
  # the peer's encoder stream hasn't delivered enough dynamic table entries.
  # The caller must wait for the table to grow, then decode raw_payload manually.
  class BlockedHeadersFrame < Frame
    getter raw_payload : Bytes
    getter required_insert_count : UInt64

    def initialize(@raw_payload, @required_insert_count)
    end

    def type : FrameType; FrameType::HEADERS; end
    def encode(io : IO); end
  end

  abstract class Frame
    def self.decode(io : IO, qpack_decoder : QPACK::Decoder? = nil) : Frame
      type_val = QUIC::VarInt.decode(io)
      length = QUIC::VarInt.decode(io)

      case type_val
      when FrameType::DATA.to_u64
        buf = Bytes.new(length)
        io.read_fully(buf)
        DataFrame.new(buf)
      when FrameType::HEADERS.to_u64
        buf = Bytes.new(length)
        io.read_fully(buf)
        begin
          headers = (qpack_decoder || QPACK::Decoder.new).decode(buf)
          HeadersFrame.new(headers)
        rescue e : QPACK::QpackBlockedError
          BlockedHeadersFrame.new(buf, e.required_insert_count)
        end
      when FrameType::SETTINGS.to_u64
        # Read the payload into a buffer so we can iterate without io.pos
        # (which raises on non-seekable IOs such as StreamSocket or MockSocket).
        buf = Bytes.new(length)
        io.read_fully(buf)
        settings = {} of UInt64 => UInt64
        settings_io = IO::Memory.new(buf)
        while settings_io.pos < settings_io.size
          k = QUIC::VarInt.decode(settings_io)
          v = QUIC::VarInt.decode(settings_io)
          settings[k] = v
        end
        frame = SettingsFrame.new
        frame.settings = settings
        frame
      when FrameType::PUSH_PROMISE.to_u64
        buf = Bytes.new(length)
        io.read_fully(buf)
        PushPromiseFrame.new
      when FrameType::GOAWAY.to_u64
        buf = Bytes.new(length)
        io.read_fully(buf)
        stream_id = QUIC::VarInt.decode(IO::Memory.new(buf))
        GoAwayFrame.new(stream_id)
      when 0xF0700_u64, 0xF0701_u64
        # PRIORITY_UPDATE (RFC 9218) — parse and expose, no enforcement.
        buf = Bytes.new(length)
        io.read_fully(buf)
        buf_io = IO::Memory.new(buf)
        element_id = QUIC::VarInt.decode(buf_io)
        pfv = buf_io.pos < buf.size ? String.new(buf[buf_io.pos..]) : ""
        PriorityUpdateFrame.new(element_id, pfv, type_val == 0xF0700_u64)
      else
        # Unknown frame type — must be silently ignored (RFC 9114 §9).
        buf = Bytes.new(length)
        io.read_fully(buf)
        UnknownFrame.new(type_val, buf)
      end
    end
  end
end
