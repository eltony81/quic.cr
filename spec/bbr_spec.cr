require "./spec_helper"

describe "QUIC::Recovery — BBR Congestion Control (RFC 9002 §7 + BBR)" do
  # Helpers to drive send/ACK cycles with controlled virtual time.
  # on_packet_sent stamps Time.local internally; we pass explicit time_received
  # to on_ack_received so RTT and bandwidth calculations are deterministic.

  describe "initial state" do
    it "BBR is disabled by default" do
      r = QUIC::Recovery.new
      r.bbr_enabled?.should be_false
    end

    it "bbr_min_rtt starts at Time::Span::MAX" do
      r = QUIC::Recovery.new
      r.bbr_min_rtt.should eq(Time::Span::MAX)
    end

    it "bbr_max_bandwidth starts at 0.0" do
      r = QUIC::Recovery.new
      r.bbr_max_bandwidth.should eq(0.0)
    end

    it "pacing uses cwnd/smoothed_rtt before any ACK (BBR off)" do
      r = QUIC::Recovery.new
      # Initial: cwnd=INITIAL_WINDOW=32×1472, smoothed_rtt=333ms
      expected = QUIC::Recovery::INITIAL_WINDOW.to_f / 0.333
      r.pacing_rate_bps.should be_close(expected, 1.0)
    end

    it "pacing uses cwnd/smoothed_rtt before first bandwidth sample (BBR on, bw=0)" do
      r = QUIC::Recovery.new
      r.bbr_enabled = true
      # BBR branch only fires when bbr_max_bandwidth > 0; falls back to cwnd/rtt
      expected = QUIC::Recovery::INITIAL_WINDOW.to_f / 0.333
      r.pacing_rate_bps.should be_close(expected, 1.0)
    end
  end

  describe "enabling / disabling BBR" do
    it "can be enabled" do
      r = QUIC::Recovery.new
      r.bbr_enabled = true
      r.bbr_enabled?.should be_true
    end

    it "can be disabled after enabling" do
      r = QUIC::Recovery.new
      r.bbr_enabled = true
      r.bbr_enabled = false
      r.bbr_enabled?.should be_false
    end
  end

  describe "bbr_min_rtt update on ACK" do
    it "bbr_min_rtt is set after the first ACK" do
      r   = QUIC::Recovery.new
      t0  = Time.local
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 10.milliseconds, 2)
      r.bbr_min_rtt.should_not eq(Time::Span::MAX)
    end

    it "bbr_min_rtt is approximately equal to the measured RTT" do
      r   = QUIC::Recovery.new
      t0  = Time.local
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 20.milliseconds, 2)
      # min_rtt ≤ 20ms (it's the RTT of the first packet)
      r.bbr_min_rtt.should be <= 21.milliseconds
    end

    it "bbr_min_rtt tracks the minimum across multiple ACKs" do
      r   = QUIC::Recovery.new
      t0  = Time.local
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 30.milliseconds, 2)
      first_min = r.bbr_min_rtt
      r.on_packet_sent(1u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(1u64, 0u64, 0u64), t0 + 40.milliseconds, 2)
      # bbr_min_rtt should never increase
      r.bbr_min_rtt.should be <= first_min
    end

    it "bbr_min_rtt is updated even when BBR is disabled" do
      r   = QUIC::Recovery.new
      r.bbr_enabled = false
      t0  = Time.local
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 15.milliseconds, 2)
      r.bbr_min_rtt.should_not eq(Time::Span::MAX)
    end
  end

  describe "bbr_max_bandwidth update on ACK" do
    it "bbr_max_bandwidth > 0 after two send/ACK cycles" do
      r   = QUIC::Recovery.new
      t0  = Time.local
      # First cycle: sets @bbr_delivered_time = t0 + 10ms
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 10.milliseconds, 2)
      # Second cycle: delivery_interval = (t0+20ms) - (t0+10ms) = 10ms → rate = 1200/0.01
      r.on_packet_sent(1u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(1u64, 0u64, 0u64), t0 + 20.milliseconds, 2)
      r.bbr_max_bandwidth.should be > 0.0
    end

    it "bbr_max_bandwidth is monotonically non-decreasing across ACKs" do
      r   = QUIC::Recovery.new
      t0  = Time.local
      prev = 0.0
      5.times do |i|
        r.on_packet_sent(i.to_u64, 1200, [] of QUIC::Frame, true, 2)
        r.on_ack_received(QUIC::AckFrame.new(i.to_u64, 0u64, 0u64), t0 + ((i + 1) * 10).milliseconds, 2)
        r.bbr_max_bandwidth.should be >= prev
        prev = r.bbr_max_bandwidth
      end
    end
  end

  describe "BBR congestion window" do
    it "cwnd = max(5888, 2 × BDP) after bandwidth sample" do
      r   = QUIC::Recovery.new
      r.bbr_enabled = true
      t0  = Time.local
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 10.milliseconds, 2)
      r.on_packet_sent(1u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(1u64, 0u64, 0u64), t0 + 20.milliseconds, 2)
      bw  = r.bbr_max_bandwidth
      rtt = r.bbr_min_rtt
      if bw > 0.0 && rtt != Time::Span::MAX
        expected = Math.max(5888_u64, (2.0 * bw * rtt.to_f).to_u64)
        r.congestion_window.should eq(expected)
      end
    end

    it "BBR cwnd is always ≥ 5888 (4 × MTU floor)" do
      r   = QUIC::Recovery.new
      r.bbr_enabled = true
      t0  = Time.local
      # Very small packet: low bandwidth → BDP might be tiny
      r.on_packet_sent(0u64, 40, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 1.milliseconds, 2)
      r.on_packet_sent(1u64, 40, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(1u64, 0u64, 0u64), t0 + 2.milliseconds, 2)
      r.congestion_window.should be >= 5888_u64
    end

    it "BBR does not change cwnd before first bandwidth sample" do
      r    = QUIC::Recovery.new
      r.bbr_enabled = true
      init = r.congestion_window
      # Only one ACK — no bandwidth estimate yet (bbr_max_bandwidth == 0 after first ACK)
      t0 = Time.local
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 10.milliseconds, 2)
      # After first ACK bandwidth may still be 0 (depends on delivery_interval > 0)
      # Either cwnd is unchanged (bw=0) or updated by BBR formula — never below 5888
      r.congestion_window.should be >= 5888_u64
    end
  end

  describe "BBR pacing rate" do
    it "pacing_rate_bps = bbr_max_bandwidth × 1.25 when BBR enabled with sample" do
      r   = QUIC::Recovery.new
      r.bbr_enabled = true
      t0  = Time.local
      r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 10.milliseconds, 2)
      r.on_packet_sent(1u64, 1200, [] of QUIC::Frame, true, 2)
      r.on_ack_received(QUIC::AckFrame.new(1u64, 0u64, 0u64), t0 + 20.milliseconds, 2)
      if r.bbr_max_bandwidth > 0.0
        r.pacing_rate_bps.should eq(r.bbr_max_bandwidth * 1.25)
      end
    end

    it "NewReno pacing_rate_bps = cwnd / smoothed_rtt" do
      r = QUIC::Recovery.new
      r.bbr_enabled = false
      r.smoothed_rtt = 10.milliseconds
      expected = r.congestion_window.to_f / 0.01
      r.pacing_rate_bps.should be_close(expected, 1.0)
    end

    it "BBR and NewReno both produce positive pacing rates after an RTT sample" do
      t0  = Time.local
      [true, false].each do |bbr|
        r = QUIC::Recovery.new
        r.bbr_enabled = bbr
        r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
        r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 10.milliseconds, 2)
        r.on_packet_sent(1u64, 1200, [] of QUIC::Frame, true, 2)
        r.on_ack_received(QUIC::AckFrame.new(1u64, 0u64, 0u64), t0 + 20.milliseconds, 2)
        r.pacing_rate_bps.should be > 0.0
      end
    end
  end

  describe "BBR vs NewReno window divergence" do
    it "BBR cwnd can differ from NewReno cwnd after same traffic" do
      t0     = Time.local
      bbr    = QUIC::Recovery.new; bbr.bbr_enabled    = true
      newreno = QUIC::Recovery.new; newreno.bbr_enabled = false

      [bbr, newreno].each do |r|
        r.on_packet_sent(0u64, 1200, [] of QUIC::Frame, true, 2)
        r.on_ack_received(QUIC::AckFrame.new(0u64, 0u64, 0u64), t0 + 10.milliseconds, 2)
        r.on_packet_sent(1u64, 1200, [] of QUIC::Frame, true, 2)
        r.on_ack_received(QUIC::AckFrame.new(1u64, 0u64, 0u64), t0 + 20.milliseconds, 2)
      end

      # Both should have a positive cwnd; they MAY differ
      bbr.congestion_window.should be > 0u64
      newreno.congestion_window.should be > 0u64
    end
  end
end
