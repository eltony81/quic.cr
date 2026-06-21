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
        settings = {} of UInt64 => UInt64
        start = io.pos
        while io.pos - start < length
          k = QUIC::VarInt.decode(io)
          v = QUIC::VarInt.decode(io)
          settings[k] = v
        end
        frame = SettingsFrame.new
        frame.settings = settings
        frame
      else
        # Fallback/ignore unknown types
        buf = Bytes.new(length)
        io.read_fully(buf)
        DataFrame.new(buf)
      end
    end
  end
end
