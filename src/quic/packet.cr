module QUIC
  enum PacketType : UInt8
    Initial   = 0x00
    ZeroRTT   = 0x01
    Handshake = 0x02
    Retry     = 0x03
    Short     = 0x04 # 1-RTT
  end

  abstract class Packet
    abstract def type : PacketType
    property frames = [] of Frame
    property packet_number : UInt64 = 0

    abstract def encode(io : IO)
    abstract def encode_header(io : IO)
    abstract def first_byte : UInt8
  end

  class LongHeaderPacket < Packet
    getter type : PacketType
    getter version : UInt32
    getter dcid : Bytes
    getter scid : Bytes
    property token : Bytes

    def initialize(@type, @version, @dcid, @scid, @frames = [] of Frame, @token = Bytes.empty)
    end

    def first_byte : UInt8
      type_val = case @type
                 when PacketType::Initial   then 0x00_u8
                 when PacketType::ZeroRTT   then 0x01_u8
                 when PacketType::Handshake then 0x02_u8
                 else 0x00_u8
                 end
      0xc0_u8 | (type_val << 4) | 0x03_u8
    end

    def encode_header(io : IO)
      io.write_byte first_byte
      IO::ByteFormat::NetworkEndian.encode(@version, io)
      io.write_byte @dcid.size.to_u8
      io.write @dcid
      io.write_byte @scid.size.to_u8
      io.write @scid
      if @type == PacketType::Initial
        io.write VarInt.encode(@token.size.to_u64)
        io.write @token
      end
    end

    def encode(io : IO)
      encode_header(io)
      pn_len = 4
      payload_io = IO::Memory.new
      @frames.each &.encode(payload_io)
      payload = payload_io.to_slice
      
      length = pn_len + payload.size
      io.write VarInt.encode(length.to_u64)
      IO::ByteFormat::NetworkEndian.encode(@packet_number.to_u32, io)
      io.write payload
    end
  end

  class RetryPacket < Packet
    getter version : UInt32
    getter dcid : Bytes
    getter scid : Bytes
    getter token : Bytes
    getter tag : Bytes

    def initialize(@version, @dcid, @scid, @token, @tag)
    end

    def type : PacketType
      PacketType::Retry
    end

    def first_byte : UInt8
      0xf0_u8
    end

    def encode_header(io : IO)
      io.write_byte first_byte
      IO::ByteFormat::NetworkEndian.encode(@version, io)
      io.write_byte @dcid.size.to_u8
      io.write @dcid
      io.write_byte @scid.size.to_u8
      io.write @scid
    end

    def encode_without_tag(io : IO)
      encode_header(io)
      io.write @token
    end

    def encode(io : IO)
      encode_without_tag(io)
      io.write @tag
    end
  end

  class VersionNegotiationPacket < Packet
    getter dcid : Bytes
    getter scid : Bytes
    getter supported_versions : Array(UInt32)

    def initialize(@dcid, @scid, @supported_versions)
    end

    def type : PacketType
      PacketType::Initial # Not really a type, but satisfies abstract
    end

    def first_byte : UInt8
      0x80_u8 | (Random::Secure.rand(64).to_u8) # RFC says random except MSB
    end

    def encode_header(io : IO)
      io.write_byte first_byte
      IO::ByteFormat::NetworkEndian.encode(0x00000000_u32, io) # Version 0
      io.write_byte @dcid.size.to_u8
      io.write @dcid
      io.write_byte @scid.size.to_u8
      io.write @scid
    end

    def encode(io : IO)
      encode_header(io)
      @supported_versions.each do |v|
        IO::ByteFormat::NetworkEndian.encode(v, io)
      end
    end
  end

  class ShortHeaderPacket < Packet
    def type : PacketType
      PacketType::Short
    end

    getter dcid : Bytes
    # RFC 9001 §6: KEY_PHASE bit (0x04) indicates which 1-RTT key generation is
    # in use.  Covered by header protection (within the 0x1f short-header mask,
    # RFC 9001 §5.4.1) so the peer only sees the true value after unprotecting.
    property key_phase : UInt8 = 0

    def initialize(@dcid, @frames = [] of Frame)
    end

    def first_byte : UInt8
      pn_len_encoded = 0x03_u8
      # RFC 9000 §17.4: spin bit (0x20) SHOULD be randomised (greased) when not
      # actively used for RTT measurement, to prevent ossification by middleboxes.
      # The spin bit is not covered by header protection (RFC 9001 §5.4.1).
      spin = Random.rand(2) == 1 ? 0x20_u8 : 0x00_u8
      kp   = @key_phase != 0 ? 0x04_u8 : 0x00_u8
      0x40_u8 | spin | kp | pn_len_encoded
    end

    def encode_header(io : IO)
      io.write_byte first_byte
      io.write @dcid
    end

    def encode(io : IO)
      encode_header(io)
      IO::ByteFormat::NetworkEndian.encode(@packet_number.to_u32, io)
      @frames.each &.encode(io)
    end
  end
end
