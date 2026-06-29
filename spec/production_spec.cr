require "./spec_helper"

describe "Production Engineering" do
  describe "Graceful Shutdown" do
    it "H3::Server responds to shutdown" do
      router = H3::Router.new
      server = H3::Server.new(router)
      server.responds_to?(:shutdown).should be_true
    end
  end

  describe "Connection ID Rotation (RFC 9000 §5.1)" do
    it "NewConnectionIdFrame encodes with type byte 0x18" do
      cid   = Random::Secure.random_bytes(8)
      token = Random::Secure.random_bytes(16)
      frame = QUIC::NewConnectionIdFrame.new(1_u64, 0_u64, cid, token)

      io = IO::Memory.new
      frame.encode(io)
      raw = io.to_slice

      raw.size.should be > 0
      raw[0].should eq(0x18_u8)
    end

    it "NewConnectionIdFrame roundtrips sequence_number and retire_prior_to" do
      cid   = Random::Secure.random_bytes(8)
      token = Random::Secure.random_bytes(16)
      frame = QUIC::NewConnectionIdFrame.new(5_u64, 2_u64, cid, token)

      io = IO::Memory.new
      frame.encode(io)
      io.rewind

      decoded = QUIC::Frame.decode(io).as(QUIC::NewConnectionIdFrame)
      decoded.sequence_number.should eq(5_u64)
      decoded.retire_prior_to.should eq(2_u64)
      decoded.connection_id.should eq(cid)
      decoded.stateless_reset_token.should eq(token)
    end

    it "RetireConnectionIdFrame encodes with type byte 0x19" do
      frame = QUIC::RetireConnectionIdFrame.new(2_u64)
      io = IO::Memory.new
      frame.encode(io)
      raw = io.to_slice
      raw[0].should eq(0x19_u8)
    end

    it "RetireConnectionIdFrame roundtrips sequence_number" do
      frame = QUIC::RetireConnectionIdFrame.new(7_u64)
      io = IO::Memory.new
      frame.encode(io)
      io.rewind
      decoded = QUIC::Frame.decode(io).as(QUIC::RetireConnectionIdFrame)
      decoded.sequence_number.should eq(7_u64)
    end

    it "Connection exposes peer_cid_count starting at 0" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: false)
      conn.peer_cid_count.should eq(0)
    end
  end

  describe "Memory stability" do
    it "does not grow RSS unboundedly after 200 connection open/close cycles" do
      GC.collect
      rss_before = File.read("/proc/self/status")
        .scan(/VmRSS:\s+(\d+)/)
        .first?.try(&.[1].to_i) || 0

      200.times do
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.close(0_u64, "done")
      end

      GC.collect
      rss_after = File.read("/proc/self/status")
        .scan(/VmRSS:\s+(\d+)/)
        .first?.try(&.[1].to_i) || 0

      # Allow up to 3× growth — Boehm GC is lazy and may not have collected
      # everything, but unbounded C-heap leaks would exceed this threshold.
      growth = rss_after.to_f / [rss_before, 1].max
      growth.should be <= 3.0
    end
  end
end
