require "./spec_helper"

# RFC 9000 §10.1 — Idle Timeout
#
# Each endpoint sends max_idle_timeout in transport parameters (milliseconds).
# Effective timeout = min(local, remote), ignoring zeros.
# After the idle period expires post-handshake, the connection is closed
# silently (no CONNECTION_CLOSE frame sent).

describe "Idle Timeout (RFC 9000 §10.1)" do
  describe "Config" do
    it "defaults to 30 000 ms" do
      QUIC::Config.new.max_idle_timeout.should eq(30_000_u64)
    end
  end

  describe "tick() — pre-handshake guard" do
    it "does not close connection before handshake even with 1ms timeout" do
      cfg = QUIC::Config.new
      cfg.max_idle_timeout = 1_u64  # would fire immediately if guard were absent
      conn = QUIC::Connection.new(cfg, is_server: true)
      # Simulate far future — handshake never completed
      conn.tick(Time.local + 1.year)
      conn.closed?.should be_false
    end
  end

  describe "next_event_time() — idle deadline" do
    it "returns approx now + max_idle_timeout when no PTO/loss timers" do
      cfg = QUIC::Config.new
      cfg.max_idle_timeout = 5_000_u64  # 5 seconds
      t0 = Time.local
      conn = QUIC::Connection.new(cfg, is_server: true)

      event = conn.next_event_time
      event.should_not be_nil
      # @last_recv_time is initialised to Time.local at construction, so
      # deadline should be very close to t0 + 5s.
      delta = event.not_nil! - t0
      delta.total_seconds.should be_close(5.0, 0.5)
    end

    it "returns nil when max_idle_timeout is 0 (disabled) and no in-flight packets" do
      cfg = QUIC::Config.new
      cfg.max_idle_timeout = 0_u64
      conn = QUIC::Connection.new(cfg, is_server: true)
      conn.next_event_time.should be_nil
    end

    it "idle deadline advances after recv() resets the timer" do
      cfg = QUIC::Config.new
      cfg.max_idle_timeout = 5_000_u64
      conn = QUIC::Connection.new(cfg, is_server: true)

      before = conn.next_event_time.not_nil!

      # Sleep a little so Time.local advances, then call recv — which resets
      # @last_recv_time to the new Time.local.  Garbage bytes are fine: the
      # packet loop still runs (and updates the timer) before returning.
      sleep 50.milliseconds
      conn.recv(Bytes.new(32, 0_u8))

      after = conn.next_event_time.not_nil!
      # The deadline should have shifted forward by ≈ 50ms
      (after - before).total_milliseconds.should be > 30
    end
  end

  describe "TransportParameters — max_idle_timeout field" do
    it "roundtrips 15 000 ms through encode/decode" do
      tp = QUIC::TransportParameters.new
      tp.max_idle_timeout = 15_000_u64

      io = IO::Memory.new
      tp.encode(io)
      io.rewind
      decoded = QUIC::TransportParameters.decode(io)

      decoded.max_idle_timeout.should eq(15_000_u64)
    end

    it "encodes 0 as disabled (decoded value is 0)" do
      tp = QUIC::TransportParameters.new
      tp.max_idle_timeout = 0_u64

      io = IO::Memory.new
      tp.encode(io)
      io.rewind
      decoded = QUIC::TransportParameters.decode(io)

      decoded.max_idle_timeout.should eq(0_u64)
    end
  end
end
