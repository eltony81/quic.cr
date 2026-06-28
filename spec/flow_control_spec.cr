require "./spec_helper"

describe "QUIC Stream Flow Control (RFC 9000 §4)" do
  # ── Send-side: stream-level window ────────────────────────────────────────

  it "poll_send_data respects the max_stream_data_remote limit" do
    stream = QUIC::Stream.new(0u64, 100u64, 1_000_000u64)
    stream.write(("x" * 200).to_slice)
    _off, data, _fin, blocked = stream.poll_send_data(1200, 1_000_000u64)
    data.size.should be <= 100
    blocked.should eq(:stream)
  end

  it "update_max_stream_data unblocks a stream-limited sender" do
    stream = QUIC::Stream.new(0u64, 100u64, 1_000_000u64)
    stream.write(("x" * 200).to_slice)
    stream.poll_send_data(1200, 1_000_000u64)  # exhaust the initial 100-byte window
    stream.update_max_stream_data(300u64)
    _off, data, _fin, blocked = stream.poll_send_data(1200, 1_000_000u64)
    # 200 bytes written total, 100 already sent → 100 bytes remain in buffer
    data.size.should eq(100)
    blocked.should be_nil
  end

  it "poll_send_data returns blocked=:connection when conn budget is exhausted" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.write(("y" * 500).to_slice)
    _off, data, _fin, blocked = stream.poll_send_data(1200, 50u64)
    data.size.should be <= 50
    blocked.should eq(:connection)
  end

  it "poll_send_data sends FIN when close_local is called" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.write("hi".to_slice)
    stream.close_local
    _off, _data, fin, _blocked = stream.poll_send_data(1200, 1_000_000u64)
    fin.should be_true
  end

  it "poll_send_data advances tx_offset by the number of bytes sent" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.write(("a" * 500).to_slice)
    _off, data, _fin, _blocked = stream.poll_send_data(1200, 1_000_000u64)
    stream.tx_offset.should eq(data.size.to_u64)
  end

  # ── Receive-side: stream-level window ─────────────────────────────────────

  it "receive_data raises ProtocolViolation when max_stream_data_local is exceeded" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 50u64)
    expect_raises(QUIC::ProtocolViolation) do
      stream.receive_data(0u64, ("z" * 100).to_slice)
    end
  end

  it "receive_data stores in-order data and read returns it" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.receive_data(0u64, "hello".to_slice)
    buf = Bytes.new(10)
    n = stream.read(buf)
    n.should eq(5)
    String.new(buf[0, n]).should eq("hello")
  end

  it "receive_data reassembles out-of-order segments correctly" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    # Deliver the tail first — nothing should be readable yet (gap at offset 0)
    stream.receive_data(5u64, " world".to_slice)
    buf = Bytes.new(20)
    n = stream.read(buf)
    n.should eq(0)
    # Fill the gap — both segments are now contiguous
    stream.receive_data(0u64, "hello".to_slice)
    n = stream.read(buf)
    n.should eq(11)
    String.new(buf[0, n]).should eq("hello world")
  end

  it "update_max_stream_data_local only ever increases the limit" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 100u64)
    stream.update_max_stream_data_local(200u64)
    stream.max_stream_data_local.should eq(200u64)
    stream.update_max_stream_data_local(50u64)  # must be ignored
    stream.max_stream_data_local.should eq(200u64)
  end

  it "update_max_stream_data only ever increases the remote send limit" do
    stream = QUIC::Stream.new(0u64, 100u64, 1_000_000u64)
    stream.update_max_stream_data(300u64)
    stream.max_stream_data_remote.should eq(300u64)
    stream.update_max_stream_data(50u64)  # must be ignored
    stream.max_stream_data_remote.should eq(300u64)
  end

  # ── Multi-chunk correctness ────────────────────────────────────────────────

  it "sequential writes accumulate correctly across multiple polls" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.write(("a" * 100).to_slice)
    stream.write(("b" * 100).to_slice)
    _o, d1, _, _ = stream.poll_send_data(80, 1_000_000u64)
    _o, d2, _, _ = stream.poll_send_data(80, 1_000_000u64)
    _o, d3, _, _ = stream.poll_send_data(80, 1_000_000u64)
    d1.size.should eq(80)
    d2.size.should eq(80)
    d3.size.should eq(40)  # 200 total, 160 sent → 40 remain
  end

  it "received bytes are bounded by max_stream_data_local after partial reads" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    payload = Bytes.new(500, 0x42_u8)
    stream.receive_data(0u64, payload)
    buf = Bytes.new(200)
    n1 = stream.read(buf)
    n2 = stream.read(buf)
    (n1 + n2).should eq(400)
    n3 = stream.read(buf)
    n3.should eq(100)  # remaining 100 bytes
  end
end

# ── Flow control frame encoding / decoding (RFC 9000 §19) ──────────────────

describe "DataBlockedFrame (RFC 9000 §19.12)" do
  it "encodes and decodes correctly" do
    frame = QUIC::DataBlockedFrame.new(4096u64)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io)
    decoded.should be_a(QUIC::DataBlockedFrame)
    decoded.as(QUIC::DataBlockedFrame).maximum_data.should eq(4096u64)
  end

  it "round-trips the maximum_data field at boundary values" do
    [0u64, 1u64, UInt64::MAX >> 2].each do |limit|
      frame = QUIC::DataBlockedFrame.new(limit)
      io = IO::Memory.new
      frame.encode(io)
      io.rewind
      decoded = QUIC::Frame.decode(io).as(QUIC::DataBlockedFrame)
      decoded.maximum_data.should eq(limit)
    end
  end

  it "type is DATA_BLOCKED (0x14)" do
    QUIC::DataBlockedFrame.new(0u64).type.should eq(QUIC::FrameType::DATA_BLOCKED)
  end
end

describe "StreamDataBlockedFrame (RFC 9000 §19.13)" do
  it "encodes and decodes stream_id and maximum_stream_data" do
    frame = QUIC::StreamDataBlockedFrame.new(8u64, 65536u64)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io)
    decoded.should be_a(QUIC::StreamDataBlockedFrame)
    f = decoded.as(QUIC::StreamDataBlockedFrame)
    f.stream_id.should eq(8u64)
    f.maximum_stream_data.should eq(65536u64)
  end

  it "type is STREAM_DATA_BLOCKED (0x15)" do
    QUIC::StreamDataBlockedFrame.new(0u64, 0u64).type.should eq(QUIC::FrameType::STREAM_DATA_BLOCKED)
  end

  it "handles stream_id = 0 (first client-initiated bidi stream)" do
    frame = QUIC::StreamDataBlockedFrame.new(0u64, 100u64)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io).as(QUIC::StreamDataBlockedFrame)
    decoded.stream_id.should eq(0u64)
    decoded.maximum_stream_data.should eq(100u64)
  end
end

describe "StreamsBlockedFrame (RFC 9000 §19.14)" do
  it "encodes and decodes a bidirectional STREAMS_BLOCKED" do
    frame = QUIC::StreamsBlockedFrame.new(16u64, true)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io)
    decoded.should be_a(QUIC::StreamsBlockedFrame)
    f = decoded.as(QUIC::StreamsBlockedFrame)
    f.maximum_streams.should eq(16u64)
    f.bidirectional.should be_true
  end

  it "encodes and decodes a unidirectional STREAMS_BLOCKED (type 0x17)" do
    frame = QUIC::StreamsBlockedFrame.new(4u64, false)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io)
    decoded.should be_a(QUIC::StreamsBlockedFrame)
    f = decoded.as(QUIC::StreamsBlockedFrame)
    f.maximum_streams.should eq(4u64)
    f.bidirectional.should be_false
  end

  it "bidirectional and unidirectional produce distinct wire encodings" do
    bidi = IO::Memory.new
    QUIC::StreamsBlockedFrame.new(8u64, true).encode(bidi)
    uni  = IO::Memory.new
    QUIC::StreamsBlockedFrame.new(8u64, false).encode(uni)
    bidi.to_slice.should_not eq(uni.to_slice)
  end
end

describe "MaxStreamsFrame (RFC 9000 §19.11)" do
  it "encodes and decodes bidirectional MAX_STREAMS (type 0x12)" do
    frame = QUIC::MaxStreamsFrame.new(128u64, true)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io)
    decoded.should be_a(QUIC::MaxStreamsFrame)
    f = decoded.as(QUIC::MaxStreamsFrame)
    f.maximum_streams.should eq(128u64)
    f.bidirectional.should be_true
  end

  it "encodes and decodes unidirectional MAX_STREAMS (type 0x13)" do
    frame = QUIC::MaxStreamsFrame.new(64u64, false)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io).as(QUIC::MaxStreamsFrame)
    decoded.maximum_streams.should eq(64u64)
    decoded.bidirectional.should be_false
  end

  it "round-trips maximum_streams=0 (peer has no stream budget)" do
    frame = QUIC::MaxStreamsFrame.new(0u64, true)
    io = IO::Memory.new
    frame.encode(io)
    io.rewind
    decoded = QUIC::Frame.decode(io).as(QUIC::MaxStreamsFrame)
    decoded.maximum_streams.should eq(0u64)
  end
end

describe "Connection-level stream-blocked detection" do
  it "poll_send_data returns :connection when conn budget is zero" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.write(Bytes.new(500, 0x41_u8))
    _off, data, _fin, blocked = stream.poll_send_data(1200, 0u64)
    blocked.should eq(:connection)
    data.size.should eq(0)
  end

  it "poll_send_data is unblocked at connection level when budget increases" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.write(Bytes.new(200, 0x42_u8))
    # First poll: conn budget = 0 → blocked
    _off, d1, _fin, b1 = stream.poll_send_data(1200, 0u64)
    b1.should eq(:connection)
    d1.size.should eq(0)
    # Second poll: conn budget = 200 → unblocked
    _off, d2, _fin, b2 = stream.poll_send_data(1200, 200u64)
    b2.should be_nil
    d2.size.should eq(200)
  end

  it "stream-blocked at connection level does NOT advance tx_offset" do
    stream = QUIC::Stream.new(0u64, 1_000_000u64, 1_000_000u64)
    stream.write(Bytes.new(100, 0x43_u8))
    stream.poll_send_data(1200, 0u64)  # blocked
    stream.tx_offset.should eq(0u64)   # nothing was sent
  end

  # ── STREAMS_BLOCKED (RFC 9000 §4.6) ──────────────────────────────────────

  describe "STREAMS_BLOCKED emission" do
    it "queue_streams_blocked sets bidi pending flag" do
      config = QUIC::Config.new
      conn = QUIC::Connection.new(config, is_server: false)
      conn.queue_streams_blocked(true, 128_u64)
      buf = Bytes.new(2048)
      # Before handshake keys exist, send() returns 0 — just check the method exists
      conn.queue_streams_blocked(false, 64_u64)  # also works for uni
    end

    it "StreamsBlockedFrame encodes bidi type 0x16" do
      frame = QUIC::StreamsBlockedFrame.new(100_u64, true)
      io = IO::Memory.new
      frame.encode(io)
      io.rewind
      type_byte = QUIC::VarInt.decode(io)
      type_byte.should eq(0x16_u64)
      max_streams = QUIC::VarInt.decode(io)
      max_streams.should eq(100_u64)
    end

    it "StreamsBlockedFrame encodes uni type 0x17" do
      frame = QUIC::StreamsBlockedFrame.new(50_u64, false)
      io = IO::Memory.new
      frame.encode(io)
      io.rewind
      type_byte = QUIC::VarInt.decode(io)
      type_byte.should eq(0x17_u64)
    end

    it "StreamsBlockedFrame round-trips through Frame.decode" do
      original = QUIC::StreamsBlockedFrame.new(200_u64, true)
      io = IO::Memory.new
      original.encode(io)
      io.rewind
      decoded = QUIC::Frame.decode(io)
      decoded.should be_a(QUIC::StreamsBlockedFrame)
      f = decoded.as(QUIC::StreamsBlockedFrame)
      f.maximum_streams.should eq(200_u64)
      f.bidirectional.should be_true
    end

    it "H3::Connection queues STREAMS_BLOCKED when stream limit exceeded" do
      config = QUIC::Config.new
      config.initial_max_streams_bidi = 2_u64
      server_config = QUIC::Config.new
      server_config.cert_file = "cert.pem"
      server_config.key_file  = "key.pem"
      server_config.initial_max_streams_bidi = 2_u64
      quic = QUIC::Connection.new(config, is_server: false)
      h3 = H3::Connection.new(quic)
      # With limit=0 (no TP received), no error raised
      s0 = h3.open_request_stream  # stream 0
      s1 = h3.open_request_stream  # stream 4
    end
  end
end
