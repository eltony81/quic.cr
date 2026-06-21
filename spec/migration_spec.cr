require "./spec_helper"

describe "QUIC Connection Migration" do
  describe "PATH_CHALLENGE / PATH_RESPONSE frames" do
    it "PathChallengeFrame encodes and decodes 8-byte data" do
      data = Random::Secure.random_bytes(8)
      frame = QUIC::PathChallengeFrame.new(data)

      io = IO::Memory.new
      frame.encode(io)
      io.rewind

      decoded = QUIC::Frame.decode(io)
      decoded.should be_a(QUIC::PathChallengeFrame)
      decoded.as(QUIC::PathChallengeFrame).data.should eq(data)
    end

    it "PathResponseFrame encodes and decodes 8-byte data" do
      data = Random::Secure.random_bytes(8)
      frame = QUIC::PathResponseFrame.new(data)

      io = IO::Memory.new
      frame.encode(io)
      io.rewind

      decoded = QUIC::Frame.decode(io)
      decoded.should be_a(QUIC::PathResponseFrame)
      decoded.as(QUIC::PathResponseFrame).data.should eq(data)
    end

    it "PathChallengeFrame requires exactly 8 bytes" do
      expect_raises(ArgumentError) { QUIC::PathChallengeFrame.new(Bytes.new(7)) }
      expect_raises(ArgumentError) { QUIC::PathChallengeFrame.new(Bytes.new(9)) }
    end

    it "PathResponseFrame requires exactly 8 bytes" do
      expect_raises(ArgumentError) { QUIC::PathResponseFrame.new(Bytes.new(4)) }
    end
  end

  describe "initiate_path_validation" do
    it "returns an 8-byte challenge" do
      config = QUIC::Config.new
      conn   = QUIC::Connection.new(config, is_server: false)

      challenge = conn.initiate_path_validation
      challenge.size.should eq(8)
    end

    it "resets path_validated? to false" do
      config = QUIC::Config.new
      conn   = QUIC::Connection.new(config, is_server: false)

      conn.path_validated?.should be_false
      conn.initiate_path_validation
      conn.path_validated?.should be_false
    end

    it "produces a different challenge on each call" do
      config = QUIC::Config.new
      conn   = QUIC::Connection.new(config, is_server: false)

      c1 = conn.initiate_path_validation
      c2 = conn.initiate_path_validation
      # Probability of collision with random 8 bytes is negligible
      c1.should_not eq(c2)
    end
  end

  describe "BufferPool" do
    it "leases and returns buffers without allocation" do
      pool = QUIC::BufferPool.new(1024, 4)

      b1 = pool.lease
      b1.size.should eq(1024)

      pool.return(b1)

      b2 = pool.lease
      b2.size.should eq(1024)
      # Should reuse the same underlying buffer
      b2.to_unsafe.should eq(b1.to_unsafe)
    end

    it "allocates a fresh buffer when pool is empty" do
      pool = QUIC::BufferPool.new(512, 0)
      buf = pool.lease
      buf.size.should eq(512)
    end

    it "borrow yields and auto-returns the buffer" do
      pool = QUIC::BufferPool.new(256, 2)
      yielded = nil
      pool.borrow { |b| yielded = b }
      yielded.should_not be_nil
      yielded.not_nil!.size.should eq(256)

      # After borrow, pool should have the buffer back
      b2 = pool.lease
      b2.to_unsafe.should eq(yielded.not_nil!.to_unsafe)
    end

    it "ignores buffers with wrong size on return" do
      pool = QUIC::BufferPool.new(1024, 1)
      pool.return(Bytes.new(512))  # wrong size, should be silently dropped
      buf = pool.lease
      buf.size.should eq(1024)  # still gets a correctly-sized buffer
    end
  end
end
