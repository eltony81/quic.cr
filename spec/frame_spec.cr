require "./spec_helper"

# Round-trip helper: encode a frame and decode it back
private def round_trip(frame : QUIC::Frame) : QUIC::Frame
  io = IO::Memory.new
  frame.encode(io)
  io.rewind
  QUIC::Frame.decode(io)
end

describe QUIC::Frame do
  # ── Already-covered types ────────────────────────────────────────────────────

  it "decodes a PADDING frame" do
    io = IO::Memory.new(Bytes[0x00])
    QUIC::Frame.decode(io).should be_a(QUIC::PaddingFrame)
  end

  it "decodes a PING frame" do
    round_trip(QUIC::PingFrame.new).should be_a(QUIC::PingFrame)
  end

  it "decodes a CRYPTO frame" do
    data = Bytes[0x06, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
    frame = QUIC::Frame.decode(IO::Memory.new(data)).as(QUIC::CryptoFrame)
    frame.offset.should eq(0)
    frame.data.should eq(Bytes[1, 2, 3, 4])
  end

  it "raises on unsupported frame type" do
    expect_raises(QUIC::ProtocolViolation) do
      QUIC::Frame.decode(IO::Memory.new(Bytes[0x3f]))
    end
  end

  # ── Flow-control frames ──────────────────────────────────────────────────────

  it "round-trips MaxDataFrame" do
    f = round_trip(QUIC::MaxDataFrame.new(123_456_u64)).as(QUIC::MaxDataFrame)
    f.maximum_data.should eq(123_456_u64)
  end

  it "round-trips MaxStreamDataFrame" do
    f = round_trip(QUIC::MaxStreamDataFrame.new(4_u64, 99_000_u64)).as(QUIC::MaxStreamDataFrame)
    f.stream_id.should eq(4_u64)
    f.maximum_stream_data.should eq(99_000_u64)
  end

  it "round-trips DataBlockedFrame" do
    f = round_trip(QUIC::DataBlockedFrame.new(500_u64)).as(QUIC::DataBlockedFrame)
    f.maximum_data.should eq(500_u64)
  end

  it "round-trips StreamDataBlockedFrame" do
    f = round_trip(QUIC::StreamDataBlockedFrame.new(8_u64, 1024_u64)).as(QUIC::StreamDataBlockedFrame)
    f.stream_id.should eq(8_u64)
    f.maximum_stream_data.should eq(1024_u64)
  end

  it "round-trips MaxStreamsFrame (bidirectional)" do
    f = round_trip(QUIC::MaxStreamsFrame.new(64_u64, true)).as(QUIC::MaxStreamsFrame)
    f.maximum_streams.should eq(64_u64)
    f.bidirectional.should be_true
  end

  it "round-trips MaxStreamsFrame (unidirectional)" do
    f = round_trip(QUIC::MaxStreamsFrame.new(32_u64, false)).as(QUIC::MaxStreamsFrame)
    f.bidirectional.should be_false
  end

  it "round-trips StreamsBlockedFrame (bidirectional)" do
    f = round_trip(QUIC::StreamsBlockedFrame.new(16_u64, true)).as(QUIC::StreamsBlockedFrame)
    f.maximum_streams.should eq(16_u64)
    f.bidirectional.should be_true
  end

  it "round-trips StreamsBlockedFrame (unidirectional)" do
    f = round_trip(QUIC::StreamsBlockedFrame.new(8_u64, false)).as(QUIC::StreamsBlockedFrame)
    f.bidirectional.should be_false
  end

  # ── Stream frames ────────────────────────────────────────────────────────────

  it "round-trips StreamFrame with offset and FIN" do
    f = round_trip(QUIC::StreamFrame.new(0_u64, 10_u64, "hello".to_slice, true)).as(QUIC::StreamFrame)
    f.id.should eq(0_u64)
    f.offset.should eq(10_u64)
    f.data.should eq("hello".to_slice)
    f.fin.should be_true
  end

  it "round-trips StreamFrame with no offset and no FIN" do
    f = round_trip(QUIC::StreamFrame.new(4_u64, 0_u64, "world".to_slice, false)).as(QUIC::StreamFrame)
    f.fin.should be_false
    f.data.should eq("world".to_slice)
  end

  it "round-trips ResetStreamFrame" do
    f = round_trip(QUIC::ResetStreamFrame.new(2_u64, 0_u64, 42_u64)).as(QUIC::ResetStreamFrame)
    f.id.should eq(2_u64)
    f.error_code.should eq(0_u64)
    f.final_size.should eq(42_u64)
  end

  it "round-trips StopSendingFrame" do
    f = round_trip(QUIC::StopSendingFrame.new(6_u64, 1_u64)).as(QUIC::StopSendingFrame)
    f.id.should eq(6_u64)
    f.error_code.should eq(1_u64)
  end

  # ── Acknowledgement frame ────────────────────────────────────────────────────

  it "round-trips AckFrame with no extra ranges" do
    f = round_trip(QUIC::AckFrame.new(10_u64, 0_u64, 3_u64)).as(QUIC::AckFrame)
    f.largest_acknowledged.should eq(10_u64)
    f.first_ack_range.should eq(3_u64)
    f.ack_ranges.should be_empty
  end

  it "round-trips AckFrame with extra ranges" do
    ranges = [{1_u64, 2_u64}, {0_u64, 1_u64}]
    f = round_trip(QUIC::AckFrame.new(20_u64, 5_u64, 0_u64, ranges)).as(QUIC::AckFrame)
    f.largest_acknowledged.should eq(20_u64)
    f.ack_ranges.should eq(ranges)
  end

  # ── Connection management frames ─────────────────────────────────────────────

  it "round-trips NewTokenFrame" do
    token = Bytes[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    f = round_trip(QUIC::NewTokenFrame.new(token)).as(QUIC::NewTokenFrame)
    f.token.should eq(token)
  end

  it "round-trips NewConnectionIdFrame" do
    cid   = Bytes[0xaa, 0xbb, 0xcc, 0xdd]
    reset = Bytes.new(16, 0x11_u8)
    f = round_trip(QUIC::NewConnectionIdFrame.new(1_u64, 0_u64, cid, reset)).as(QUIC::NewConnectionIdFrame)
    f.sequence_number.should eq(1_u64)
    f.retire_prior_to.should eq(0_u64)
    f.connection_id.should eq(cid)
    f.stateless_reset_token.should eq(reset)
  end

  it "round-trips RetireConnectionIdFrame" do
    f = round_trip(QUIC::RetireConnectionIdFrame.new(3_u64)).as(QUIC::RetireConnectionIdFrame)
    f.sequence_number.should eq(3_u64)
  end

  it "round-trips HandshakeDoneFrame" do
    round_trip(QUIC::HandshakeDoneFrame.new).should be_a(QUIC::HandshakeDoneFrame)
  end

  it "round-trips ConnectionCloseFrame with reason" do
    f = round_trip(QUIC::ConnectionCloseFrame.new(0x0a_u64, 0_u64, "idle timeout")).as(QUIC::ConnectionCloseFrame)
    f.error_code.should eq(0x0a_u64)
    f.reason.should eq("idle timeout")
  end

  it "round-trips DatagramFrame (with length bit)" do
    payload = "ping".to_slice
    io = IO::Memory.new
    QUIC::DatagramFrame.new(payload).encode(io)
    io.rewind
    f = QUIC::Frame.decode(io).as(QUIC::DatagramFrame)
    f.data.should eq(payload)
  end
end

describe "H3::Frame" do
  it "round-trips DataFrame" do
    io = IO::Memory.new
    H3::DataFrame.new("hello".to_slice).encode(io)
    io.rewind
    frame = H3::Frame.decode(io).as(H3::DataFrame)
    String.new(frame.data).should eq("hello")
  end

  it "round-trips SettingsFrame with multiple settings" do
    sf = H3::SettingsFrame.new
    sf.settings[0x01_u64] = 4096_u64
    sf.settings[0x07_u64] = 100_u64
    io = IO::Memory.new
    sf.encode(io)
    io.rewind
    decoded = H3::Frame.decode(io).as(H3::SettingsFrame)
    decoded.settings[0x01_u64].should eq(4096_u64)
    decoded.settings[0x07_u64].should eq(100_u64)
  end

  it "decodes a HeadersFrame using an explicit QPACK decoder" do
    headers = {":status" => "200", "content-type" => "text/plain"}
    encoder = H3::QPACK::Encoder.new
    decoder = H3::QPACK::Decoder.new
    payload = encoder.encode(headers)
    io = IO::Memory.new
    QUIC::VarInt.write(io, H3::FrameType::HEADERS.to_u64)
    QUIC::VarInt.write(io, payload.size.to_u64)
    io.write(payload)
    io.rewind
    frame = H3::Frame.decode(io, decoder).as(H3::HeadersFrame)
    frame.headers[":status"].should eq("200")
    frame.headers["content-type"].should eq("text/plain")
  end

  it "ignores unknown H3 frame types (returns UnknownFrame)" do
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x21_u64)   # unknown type
    QUIC::VarInt.write(io, 4_u64)      # length = 4
    io.write(Bytes[0x01, 0x02, 0x03, 0x04])
    io.rewind
    frame = H3::Frame.decode(io)
    # RFC 9114 §9: unknown frame types MUST be ignored — decoder returns UnknownFrame
    frame.should be_a(H3::UnknownFrame)
    frame.as(H3::UnknownFrame).raw_data.should eq(Bytes[0x01, 0x02, 0x03, 0x04])
  end

  it "decodes a GOAWAY frame" do
    io = IO::Memory.new
    QUIC::VarInt.write(io, H3::FrameType::GOAWAY.to_u64)
    QUIC::VarInt.write(io, 1_u64)
    io.write(Bytes[0x00])
    io.rewind
    frame = H3::Frame.decode(io)
    frame.should be_a(H3::GoAwayFrame)
    frame.as(H3::GoAwayFrame).stream_id.should eq(0_u64)
  end
end
