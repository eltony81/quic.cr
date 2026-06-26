require "./spec_helper"

describe QUIC::Stream do
  # ── Initial state ────────────────────────────────────────────────────────────

  it "starts in Idle state" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.state.should eq(QUIC::StreamState::Idle)
  end

  it "has no send data initially" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.has_send_data?.should be_false
  end

  # ── State machine: write path ─────────────────────────────────────────────

  it "write transitions Idle → Open" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("hello".to_slice)
    stream.state.should eq(QUIC::StreamState::Open)
  end

  it "close_local on Open → HalfClosedLocal" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("x".to_slice)
    stream.close_local
    stream.state.should eq(QUIC::StreamState::HalfClosedLocal)
  end

  it "close_remote on HalfClosedLocal → Closed" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("x".to_slice)
    stream.close_local
    stream.close_remote
    stream.state.should eq(QUIC::StreamState::Closed)
  end

  # ── State machine: receive path ───────────────────────────────────────────

  it "receive_data transitions Idle → Open" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "hi".to_slice)
    stream.state.should eq(QUIC::StreamState::Open)
  end

  it "close_remote on Open → HalfClosedRemote" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "data".to_slice)
    stream.close_remote
    stream.state.should eq(QUIC::StreamState::HalfClosedRemote)
  end

  it "close_local on HalfClosedRemote → Closed" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "data".to_slice)
    stream.close_remote
    stream.close_local
    stream.state.should eq(QUIC::StreamState::Closed)
  end

  # ── Write semantics ───────────────────────────────────────────────────────

  it "write returns the number of bytes accepted" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    n = stream.write("hello".to_slice)
    n.should eq(5)
  end

  it "write returns 0 when stream is HalfClosedLocal" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("x".to_slice)
    stream.close_local
    stream.write("more".to_slice).should eq(0)
  end

  it "write returns 0 when stream is Closed" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("x".to_slice)
    stream.close_local
    stream.close_remote
    stream.write("nope".to_slice).should eq(0)
  end

  it "write buffers data beyond the flow-control window (poll_send_data gates transmission)" do
    stream = QUIC::Stream.new(0_u64, 10_u64, 1_000_000_u64)
    n = stream.write(Bytes.new(20, 0_u8))
    n.should eq(20)  # all 20 bytes buffered regardless of window
    # poll_send_data must not send beyond the 10-byte window
    _, data, _, reason = stream.poll_send_data(1000, 1_000_000_u64)
    data.size.should eq(10)
    reason.should eq(:stream)
  end

  it "update_max_stream_data unblocks transmission (not buffering)" do
    # tx_offset advances when data is polled for sending (wire-level flow control),
    # not when written to the send buffer.
    stream = QUIC::Stream.new(0_u64, 5_u64, 1_000_000_u64)
    stream.write(Bytes.new(10, 1_u8))  # buffer 10 bytes; window = 5
    stream.poll_send_data(1000, 1_000_000_u64)  # sends 5 bytes, tx_offset → 5
    # Window exhausted: poll returns nothing until MAX_STREAM_DATA arrives.
    _, d2, _, r2 = stream.poll_send_data(1000, 1_000_000_u64)
    d2.size.should eq(0)
    r2.should eq(:stream)
    # After window increase, remaining 5 bytes can be transmitted.
    stream.update_max_stream_data(10_u64)
    _, d3, _, _ = stream.poll_send_data(1000, 1_000_000_u64)
    d3.size.should eq(5)
  end

  it "update_max_stream_data ignores lower values" do
    stream = QUIC::Stream.new(0_u64, 100_u64, 1_000_000_u64)
    stream.update_max_stream_data(50_u64)
    stream.max_stream_data_remote.should eq(100_u64)
  end

  # ── Read semantics ────────────────────────────────────────────────────────

  it "read returns received data" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "hello world".to_slice)
    buf = Bytes.new(20)
    n   = stream.read(buf)
    n.should eq(11)
    String.new(buf[0, n]).should eq("hello world")
  end

  it "read returns 0 when no data is available" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.read(Bytes.new(10)).should eq(0)
  end

  it "successive reads advance the read cursor" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "abcde".to_slice)
    buf = Bytes.new(3)
    stream.read(buf).should eq(3)
    String.new(buf).should eq("abc")
    stream.read(buf).should eq(2)
    String.new(buf[0, 2]).should eq("de")
  end

  # ── Out-of-order delivery ─────────────────────────────────────────────────

  it "buffers out-of-order segments until gap is filled" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(5_u64, " world".to_slice)  # arrives first, out of order
    buf = Bytes.new(20)
    stream.read(buf).should eq(0)                  # nothing readable yet
    stream.receive_data(0_u64, "hello".to_slice)   # fills the gap
    n = stream.read(buf)
    String.new(buf[0, n]).should eq("hello world")
  end

  it "ignores duplicate in-order segments" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "abc".to_slice)
    stream.receive_data(0_u64, "abc".to_slice)  # retransmit
    buf = Bytes.new(10)
    n = stream.read(buf)
    String.new(buf[0, n]).should eq("abc")
  end

  # ── FIN handling ──────────────────────────────────────────────────────────

  it "set_fin_offset transitions to HalfClosedRemote when all data is received" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "abc".to_slice)
    stream.set_fin_offset(3_u64)
    stream.state.should eq(QUIC::StreamState::HalfClosedRemote)
  end

  it "set_fin_offset defers transition until missing data arrives" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.set_fin_offset(5_u64)
    stream.receive_data(0_u64, "abc".to_slice)
    stream.state.should eq(QUIC::StreamState::Open)   # gap still present
    stream.receive_data(3_u64, "de".to_slice)
    stream.state.should eq(QUIC::StreamState::HalfClosedRemote)
  end

  # ── poll_send_data ────────────────────────────────────────────────────────

  it "poll_send_data returns offset 0, full data, fin=false before close_local" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("abc".to_slice)
    offset, data, fin, _ = stream.poll_send_data(1000, 1_000_000_u64)
    offset.should eq(0_u64)
    data.should eq("abc".to_slice)
    fin.should be_false
  end

  it "poll_send_data advances offset on successive calls" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("hello world".to_slice)
    off1, d1, _, _ = stream.poll_send_data(5, 1_000_000_u64)
    off1.should eq(0_u64)
    d1.size.should eq(5)
    off2, d2, _, _ = stream.poll_send_data(6, 1_000_000_u64)
    off2.should eq(5_u64)
    d2.size.should eq(6)
  end

  it "poll_send_data sets fin=true after close_local" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("hi".to_slice)
    stream.close_local
    _, _, fin, _ = stream.poll_send_data(1000, 1_000_000_u64)
    fin.should be_true
  end

  it "poll_send_data sends FIN even when there is no data" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.write("x".to_slice)
    stream.poll_send_data(1000, 1_000_000_u64)  # drain data
    stream.close_local
    _, _, fin, _ = stream.poll_send_data(1000, 1_000_000_u64)
    fin.should be_true
  end

  it "has_send_data? is true after write and false initially" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.has_send_data?.should be_false
    stream.write("x".to_slice)
    stream.has_send_data?.should be_true
  end

  # ── Flow control violations ───────────────────────────────────────────────

  it "raises ProtocolViolation when received data exceeds local flow control limit" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 10_u64)
    expect_raises(QUIC::ProtocolViolation) do
      stream.receive_data(0_u64, Bytes.new(11, 0_u8))
    end
  end

  it "receive_data ignores already-received duplicate at lower offset" do
    stream = QUIC::Stream.new(0_u64, 1_000_000_u64, 1_000_000_u64)
    stream.receive_data(0_u64, "hello".to_slice)
    stream.receive_data(0_u64, "hello".to_slice)  # duplicate — should not crash or double data
    buf = Bytes.new(20)
    n = stream.read(buf)
    String.new(buf[0, n]).should eq("hello")
  end
end
