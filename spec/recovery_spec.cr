require "./spec_helper"

describe QUIC::Recovery do
  # ── Initial state ─────────────────────────────────────────────────────────

  it "starts with initial congestion window (32 × 1472 = 47104 bytes)" do
    r = QUIC::Recovery.new
    r.congestion_window.should eq(32u64 * 1472u64)
  end

  it "starts with zero bytes in flight" do
    r = QUIC::Recovery.new
    r.bytes_in_flight.should eq(0u64)
  end

  it "can_send? is true before any packets are sent" do
    r = QUIC::Recovery.new
    r.can_send?.should be_true
  end

  it "pto_count starts at zero" do
    r = QUIC::Recovery.new
    r.pto_count.should eq(0)
  end

  it "pacing_rate_bps returns a positive default before the first RTT sample" do
    r = QUIC::Recovery.new
    r.pacing_rate_bps.should be > 0.0
  end

  it "accepts a custom initial_window" do
    r = QUIC::Recovery.new(initial_window: 8192u64)
    r.congestion_window.should eq(8192u64)
  end

  # ── #on_packet_sent ───────────────────────────────────────────────────────

  it "on_packet_sent adds ack-eliciting bytes to bytes_in_flight" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    r.bytes_in_flight.should eq(1200u64)
  end

  it "on_packet_sent does not count non-ack-eliciting (ACK-only) packets" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 40, [] of QUIC::Frame, false, 2)
    r.bytes_in_flight.should eq(0u64)
    r.sent_packet_count.should eq(0)
  end

  it "on_packet_sent accumulates bytes for multiple packets" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(1u64, 800, [] of QUIC::Frame, true, 2)
    r.bytes_in_flight.should eq(2000u64)
  end

  it "can_send? becomes false when bytes_in_flight >= congestion_window" do
    r = QUIC::Recovery.new(initial_window: 1000u64)
    r.on_packet_sent(0u64, 1000, [] of QUIC::Frame, true, 2)
    r.can_send?.should be_false
  end

  # ── #on_ack_received ─────────────────────────────────────────────────────

  it "on_ack_received removes the acked packet and decrements bytes_in_flight" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    ack = QUIC::AckFrame.new(0u64, 0u64, 0u64)
    r.on_ack_received(ack, Time.local, 2)
    r.bytes_in_flight.should eq(0u64)
    r.sent_packet_count.should eq(0)
  end

  it "on_ack_received grows congestion window during slow start" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1472, [] of QUIC::Frame, true, 2)
    cwnd_before = r.congestion_window
    ack = QUIC::AckFrame.new(0u64, 0u64, 0u64)
    r.on_ack_received(ack, Time.local, 2)
    r.congestion_window.should be > cwnd_before
  end

  it "on_ack_received updates latest_rtt for a tracked packet" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    sleep 5.milliseconds
    ack = QUIC::AckFrame.new(0u64, 0u64, 0u64)
    r.on_ack_received(ack, Time.local, 2)
    r.latest_rtt.should be >= 1.milliseconds
    r.latest_rtt.should be < 1.second
  end

  it "on_ack_received resets PTO count on success" do
    r = QUIC::Recovery.new
    r.on_pto_timeout
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    ack = QUIC::AckFrame.new(0u64, 0u64, 0u64)
    r.on_ack_received(ack, Time.local, 2)
    r.pto_count.should eq(0)
  end

  it "on_ack_received handles first_ack_range covering multiple packets" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 500, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(1u64, 500, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(2u64, 500, [] of QUIC::Frame, true, 2)
    # largest=2, first_ack_range=2 → acks pns [0,2]
    ack = QUIC::AckFrame.new(2u64, 0u64, 2u64)
    r.on_ack_received(ack, Time.local, 2)
    r.bytes_in_flight.should eq(0u64)
  end

  # ── #detect_lost_packets ─────────────────────────────────────────────────

  it "detect_lost_packets marks timed-out packets as lost" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(1u64, 1200, [] of QUIC::Frame, true, 2)
    # ACK pn=1; pn=0 becomes eligible for loss detection
    ack = QUIC::AckFrame.new(1u64, 0u64, 0u64)
    r.on_ack_received(ack, Time.local, 2)
    # Advance now by 500ms so time_since_sent(pn=0) exceeds loss_delay
    lost = r.detect_lost_packets(1u64, Time.local + 500.milliseconds, 2)
    lost.size.should eq(1)
    lost.any? { |p| p.packet_number == 0u64 }.should be_true
  end

  it "detect_lost_packets reduces congestion window on loss" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1472, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(1u64, 1472, [] of QUIC::Frame, true, 2)
    ack = QUIC::AckFrame.new(1u64, 0u64, 0u64)
    r.on_ack_received(ack, Time.local, 2)
    cwnd_before = r.congestion_window
    r.detect_lost_packets(1u64, Time.local + 500.milliseconds, 2)
    r.congestion_window.should be < cwnd_before
  end

  it "detect_lost_packets does not mark packets with pn > largest_acked as lost" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(5u64, 1200, [] of QUIC::Frame, true, 2)
    # largest_acked=0, so pn=5 must be exempt
    lost = r.detect_lost_packets(0u64, Time.local + 500.milliseconds, 2)
    lost.any? { |p| p.packet_number == 5u64 }.should be_false
  end

  # ── #on_pto_timeout ───────────────────────────────────────────────────────

  it "on_pto_timeout clears all in-flight packets and zeroes bytes_in_flight" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(1u64, 800, [] of QUIC::Frame, true, 2)
    r.on_pto_timeout
    r.bytes_in_flight.should eq(0u64)
    r.sent_packet_count.should eq(0)
  end

  it "on_pto_timeout returns the list of packets that were in flight" do
    r = QUIC::Recovery.new
    r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
    r.on_packet_sent(1u64, 800, [] of QUIC::Frame, true, 2)
    pkts = r.on_pto_timeout
    pkts.size.should eq(2)
  end

  it "on_pto_timeout increments pto_count each call" do
    r = QUIC::Recovery.new
    r.on_pto_timeout
    r.pto_count.should eq(1)
    r.on_pto_timeout
    r.pto_count.should eq(2)
  end

  # ── #pto_timeout ──────────────────────────────────────────────────────────

  it "pto_timeout returns 666ms before the first RTT sample" do
    r = QUIC::Recovery.new
    r.pto_timeout.should eq(666.milliseconds)
  end

  it "pto_timeout backs off by factor 2 after each PTO" do
    r = QUIC::Recovery.new
    r.latest_rtt = 50.milliseconds
    r.smoothed_rtt = 50.milliseconds
    r.rttvar = 10.milliseconds
    r.min_rtt = 50.milliseconds
    pto1 = r.pto_timeout
    r.on_pto_timeout
    pto2 = r.pto_timeout
    pto2.should eq(pto1 * 2)
  end

  it "pto_timeout enforces 100ms minimum floor after first RTT sample" do
    r = QUIC::Recovery.new
    r.latest_rtt = 1.milliseconds
    r.smoothed_rtt = 1.milliseconds
    r.rttvar = 1.milliseconds
    r.min_rtt = 1.milliseconds
    r.pto_timeout.should be >= 100.milliseconds
  end

  # ── #pacing_rate_bps ─────────────────────────────────────────────────────

  it "pacing_rate_bps returns cwnd/RTT when smoothed_rtt is set" do
    r = QUIC::Recovery.new
    r.latest_rtt = 10.milliseconds
    r.smoothed_rtt = 10.milliseconds
    r.min_rtt = 10.milliseconds
    r.rttvar = 1.milliseconds
    # cwnd/rtt = 47104 / 0.01 = ~4.71 MB/s
    r.pacing_rate_bps.should be > 1_000_000.0
  end
end
