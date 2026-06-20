require "./spec_helper"

describe QUIC do
  it "has a version" do
    QUIC::VERSION.should_not be_nil
  end

  it "can initialize a config" do
    config = QUIC::Config.new
    config.max_idle_timeout.should eq(30_000)
  end

  it "can initialize a connection" do
    config = QUIC::Config.new
    conn = QUIC::Connection.new(config, is_server: true)
    conn.closed?.should be_false
  end

  it "defines error types" do
    expect_raises(QUIC::InvalidPacket) do
      raise QUIC::InvalidPacket.new("test")
    end
  end
end
