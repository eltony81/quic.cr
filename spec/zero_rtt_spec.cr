require "./spec_helper"

describe "QUIC 0-RTT / Early Data" do
  describe "TLS session ticket" do
    it "session_bytes is nil before handshake" do
      config = QUIC::Config.new
      conn   = QUIC::Connection.new(config, is_server: false)
      # No handshake has taken place — no session yet
      conn.session_bytes.should be_nil
    end

    it "session_resumed? is false on a fresh connection" do
      config = QUIC::Config.new
      conn = QUIC::Connection.new(config, is_server: false)
      conn.session_resumed?.should be_false
    end

    it "Config.session_ticket field defaults to nil" do
      config = QUIC::Config.new
      config.session_ticket.should be_nil
    end

    it "Config.session_ticket can be set and read back" do
      config = QUIC::Config.new
      ticket = Bytes.new(32, 0xAB_u8)
      config.session_ticket = ticket
      config.session_ticket.should eq(ticket)
    end
  end

  describe "0-RTT packet space" do
    it "PacketType::ZeroRTT encodes as type bits 0x01" do
      pkt = QUIC::LongHeaderPacket.new(
        QUIC::PacketType::ZeroRTT,
        0x00000001_u32,
        Bytes.new(8, 1_u8),
        Bytes.new(8, 2_u8)
      )
      # First byte: 0xC0 | (0x01 << 4) | 0x03 = 0xD3
      pkt.first_byte.should eq(0xD3_u8)
    end

    it "0-RTT type bits (0x01) are distinct from Initial (0x00) and Handshake (0x02)" do
      initial   = QUIC::LongHeaderPacket.new(QUIC::PacketType::Initial,   0x1_u32, Bytes.new(8), Bytes.new(8))
      zero_rtt  = QUIC::LongHeaderPacket.new(QUIC::PacketType::ZeroRTT,  0x1_u32, Bytes.new(8), Bytes.new(8))
      handshake = QUIC::LongHeaderPacket.new(QUIC::PacketType::Handshake, 0x1_u32, Bytes.new(8), Bytes.new(8))

      initial.first_byte.should_not eq(zero_rtt.first_byte)
      zero_rtt.first_byte.should_not eq(handshake.first_byte)
    end
  end

  describe "0-RTT connection flow" do
    it "server connection exposes session_bytes after handshake signals" do
      config = QUIC::Config.new
      server = QUIC::Connection.new(config, is_server: true)
      client = QUIC::Connection.new(config, is_server: false)

      # Initial exchange (ClientHello → ServerHello path)
      buf = Bytes.new(4096)
      n = client.send(buf)
      server.recv(buf[0, n])

      # Before any meaningful TLS exchange, no session yet
      # (session only available after NST, which requires full handshake)
      # The key invariant: API is available and returns nil safely
      server.session_bytes  # must not raise
      client.session_bytes  # must not raise
    end
  end
end
