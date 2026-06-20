require "./spec_helper"

describe QUIC::VarInt do
  it "encodes 1-byte values" do
    QUIC::VarInt.encode(0x25_u64).should eq(Bytes[0x25])
  end

  it "encodes 2-byte values" do
    QUIC::VarInt.encode(151_u64).should eq(Bytes[0x40, 0x97])
  end

  it "decodes 1-byte values" do
    io = IO::Memory.new(Bytes[0x25])
    QUIC::VarInt.decode(io).should eq(0x25)
  end

  it "decodes 2-byte values" do
    io = IO::Memory.new(Bytes[0x40, 0x97])
    QUIC::VarInt.decode(io).should eq(151)
  end

  it "decodes 4-byte values" do
    io = IO::Memory.new(Bytes[0xbf, 0xff, 0xff, 0xff])
    QUIC::VarInt.decode(io).should eq(1073741823_u64)
    
    # 494878333 -> 0x9D7F3E7D
    io = IO::Memory.new(Bytes[0x9d, 0x7f, 0x3e, 0x7d])
    QUIC::VarInt.decode(io).should eq(494878333_u64)
  end

  it "decodes 8-byte values" do
    io = IO::Memory.new(Bytes[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c])
    QUIC::VarInt.decode(io).should eq(151288809941952652)
  end

  it "round trips values" do
    [0_u64, 63_u64, 64_u64, 16383_u64, 16384_u64, 1073741823_u64, 1073741824_u64, 4611686018427387903_u64].each do |val|
      encoded = QUIC::VarInt.encode(val)
      decoded = QUIC::VarInt.decode(IO::Memory.new(encoded))
      decoded.should eq(val)
    end
  end
end
