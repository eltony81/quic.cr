require "./spec_helper"

describe QUIC::Frame do
  it "decodes a PADDING frame" do
    io = IO::Memory.new(Bytes[0x00])
    frame = QUIC::Frame.decode(io)
    frame.should be_a(QUIC::PaddingFrame)
  end

  it "decodes a CRYPTO frame" do
    # Type 0x06, Offset 0, Length 4, Data [1, 2, 3, 4]
    data = Bytes[0x06, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
    io = IO::Memory.new(data)
    frame = QUIC::Frame.decode(io)
    frame.should be_a(QUIC::CryptoFrame)
    crypto = frame.as(QUIC::CryptoFrame)
    crypto.offset.should eq(0)
    crypto.data.should eq(Bytes[1, 2, 3, 4])
  end

  it "raises on unsupported frame type" do
    io = IO::Memory.new(Bytes[0x3f]) # Unallocated
    expect_raises(QUIC::ProtocolViolation) do
      QUIC::Frame.decode(io)
    end
  end
end
