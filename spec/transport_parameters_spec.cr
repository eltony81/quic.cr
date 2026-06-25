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
    decoded.max_udp_payload_size.should eq(65527)
  end

  it "always emits max_udp_payload_size (RFC 9000 §18.2)" do
    params = QUIC::TransportParameters.new
    # default value — must still appear in the wire encoding
    params.max_udp_payload_size.should eq(65527)

    io = IO::Memory.new
    params.encode(io)
    raw = io.to_slice

    # Scan the encoded bytes for parameter ID 0x03
    found = false
    mem = IO::Memory.new(raw)
    while mem.pos < mem.size
      id = QUIC::VarInt.decode(mem)
      len = QUIC::VarInt.decode(mem)
      if id == 0x03_u64
        found = true
        val_io = IO::Memory.new(raw[mem.pos, len])
        val = QUIC::VarInt.decode(val_io)
        val.should eq(65527_u64)
      end
      mem.skip(len)
    end
    found.should be_true
  end

  it "round-trips max_udp_payload_size when set to custom value" do
    params = QUIC::TransportParameters.new
    params.max_udp_payload_size = 1452_u64

    io = IO::Memory.new
    params.encode(io)
    io.rewind
    decoded = QUIC::TransportParameters.decode(io)

    decoded.max_udp_payload_size.should eq(1452_u64)
  end
end

describe QUIC::ShortHeaderPacket do
  it "grease spin bit: both 0 and 1 appear over many packets (RFC 9000 §17.4)" do
    seen_spin_set   = false
    seen_spin_clear = false

    100.times do
      pkt = QUIC::ShortHeaderPacket.new(Bytes.new(8))
      spin = pkt.first_byte & 0x20_u8
      seen_spin_set   = true if spin != 0
      seen_spin_clear = true if spin == 0
      break if seen_spin_set && seen_spin_clear
    end

    seen_spin_set.should   be_true
    seen_spin_clear.should be_true
  end

  it "always sets the fixed bit (0x40) and 4-byte packet number length (0x03)" do
    100.times do
      pkt = QUIC::ShortHeaderPacket.new(Bytes.new(8))
      (pkt.first_byte & 0x40_u8).should eq(0x40_u8) # fixed bit
      (pkt.first_byte & 0x03_u8).should eq(0x03_u8) # pn_len = 4 bytes
      (pkt.first_byte & 0x80_u8).should eq(0x00_u8) # short header
    end
  end
end

describe QUIC::Recovery do
  it "uses 2 × kInitialRtt (666ms) before first RTT sample (RFC 9002 §6.2.4)" do
    r = QUIC::Recovery.new
    # min_rtt == Time::Span::MAX means no sample yet
    r.min_rtt.should eq(Time::Span::MAX)
    r.pto_timeout.should eq(666.milliseconds)
  end

  it "uses smoothed_rtt formula after first RTT sample" do
    r = QUIC::Recovery.new
    ack = QUIC::AckFrame.new(0_u64, 0_u64, 0_u64)
    r.on_packet_sent(0_u64, 100, [] of QUIC::Frame, true, 2)
    r.on_ack_received(ack, Time.local, 2)

    r.min_rtt.should_not eq(Time::Span::MAX)
    r.pto_timeout.should be >= 100.milliseconds  # 100ms floor applies
    r.pto_timeout.should be < 666.milliseconds   # no longer using the no-sample formula
  end
end
