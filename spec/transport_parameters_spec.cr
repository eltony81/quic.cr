require "./spec_helper"

describe QUIC::TransportParameters do
  it "encodes and decodes correctly" do
    params = QUIC::TransportParameters.new
    params.max_idle_timeout = 10000
    params.initial_max_data = 1000000
    params.initial_max_stream_data_bidi_local = 500000
    params.disable_active_migration = true
    
    io = IO::Memory.new
    params.encode(io)
    
    io.rewind
    decoded = QUIC::TransportParameters.decode(io)
    
    decoded.max_idle_timeout.should eq(10000)
    decoded.initial_max_data.should eq(1000000)
    decoded.initial_max_stream_data_bidi_local.should eq(500000)
    decoded.disable_active_migration.should be_true
    
    # Defaults should remain untouched
    decoded.max_udp_payload_size.should eq(65527)
  end
end
