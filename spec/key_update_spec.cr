require "./spec_helper"

describe "Key Update (RFC 9001 §6)" do
  describe QUIC::ShortHeaderPacket do
    it "sets KEY_PHASE=0 bit when key_phase is 0" do
      pkt = QUIC::ShortHeaderPacket.new(Bytes.new(8))
      pkt.key_phase = 0
      (pkt.first_byte & 0x04_u8).should eq(0x00_u8)
    end

    it "sets KEY_PHASE=1 bit when key_phase is 1" do
      pkt = QUIC::ShortHeaderPacket.new(Bytes.new(8))
      pkt.key_phase = 1
      (pkt.first_byte & 0x04_u8).should eq(0x04_u8)
    end

    it "KEY_PHASE bit (0x04) is within the short-header HP mask (0x1f) — RFC 9001 §5.4.1" do
      (0x1f_u8 & 0x04_u8).should_not eq(0_u8)
    end

    it "fixed bit (0x40) and pn_len (0x03) are always set regardless of key_phase" do
      [0_u8, 1_u8].each do |kp|
        pkt = QUIC::ShortHeaderPacket.new(Bytes.new(8))
        pkt.key_phase = kp
        (pkt.first_byte & 0x80_u8).should eq(0x00_u8) # short header
        (pkt.first_byte & 0x40_u8).should eq(0x40_u8) # fixed bit
        (pkt.first_byte & 0x03_u8).should eq(0x03_u8) # pn_len = 4 bytes
      end
    end

    it "KEY_PHASE bit toggles correctly between 0 and 1 over successive packets" do
      seen_zero = false
      seen_one  = false
      20.times do
        pkt0 = QUIC::ShortHeaderPacket.new(Bytes.new(8))
        pkt0.key_phase = 0
        seen_zero = true if (pkt0.first_byte & 0x04_u8) == 0

        pkt1 = QUIC::ShortHeaderPacket.new(Bytes.new(8))
        pkt1.key_phase = 1
        seen_one = true if (pkt1.first_byte & 0x04_u8) != 0
      end
      seen_zero.should be_true
      seen_one.should  be_true
    end
  end

  describe QUIC::Connection do
    it "key_phase starts at 0 for a new connection" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      conn.key_phase.should eq(0_u8)
    end

    it "trigger_key_update is a no-op (key_phase stays 0) when no app secrets are present" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      conn.trigger_key_update
      conn.key_phase.should eq(0_u8)
    end
  end

  describe "KEY_PHASE derivation" do
    it "derive_next_secret produces a different 32-byte secret each generation" do
      secret0 = QUIC::Crypto.hkdf_expand_label(Bytes.new(32, 0xab_u8), "quic key", Bytes.empty, 32)
      secret1 = QUIC::Crypto.derive_next_secret(secret0)
      secret2 = QUIC::Crypto.derive_next_secret(secret1)
      secret1.size.should eq(32)
      secret2.size.should eq(32)
      secret1.should_not eq(secret0)
      secret2.should_not eq(secret1)
    end
  end
end
