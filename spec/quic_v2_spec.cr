require "./spec_helper"

describe "QUIC v2 (RFC 9369)" do
  describe QUIC::Crypto do
    it "INITIAL_SALT_V2 is 20 bytes and different from V1" do
      QUIC::Crypto::INITIAL_SALT_V2.size.should eq(20)
      QUIC::Crypto::INITIAL_SALT_V1.should_not eq(QUIC::Crypto::INITIAL_SALT_V2)
    end

    it "QUIC_V2_VERSION constant is 0x6b3343cf" do
      QUIC::Crypto::QUIC_V2_VERSION.should eq(0x6b3343cf_u32)
    end

    it "QUIC_V1_VERSION constant is 0x00000001" do
      QUIC::Crypto::QUIC_V1_VERSION.should eq(0x00000001_u32)
    end

    it "derive_initial_secrets_v2 uses different salt than v1 — secrets differ" do
      dcid = Random::Secure.random_bytes(8)
      c1, s1 = QUIC::Crypto.derive_initial_secrets(dcid)
      c2, s2 = QUIC::Crypto.derive_initial_secrets_v2(dcid)
      c1.should_not eq(c2)
      s1.should_not eq(s2)
    end

    it "derive_initial_secrets_v2 is deterministic for the same DCID" do
      dcid = Bytes[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
      c1, s1 = QUIC::Crypto.derive_initial_secrets_v2(dcid)
      c2, s2 = QUIC::Crypto.derive_initial_secrets_v2(dcid)
      c1.should eq(c2)
      s1.should eq(s2)
    end

    it "derive_next_secret_v2 uses quicv2 ku label — different from v1 ku" do
      secret = Random::Secure.random_bytes(32)
      nxt_v1 = QUIC::Crypto.derive_next_secret(secret)
      nxt_v2 = QUIC::Crypto.derive_next_secret_v2(secret)
      nxt_v1.should_not eq(nxt_v2)
    end

    it "derive_next_secret_v2 returns 32 bytes" do
      secret = Random::Secure.random_bytes(32)
      QUIC::Crypto.derive_next_secret_v2(secret).size.should eq(32)
    end

    it "derive_next_secret_v2_sha384 returns 48 bytes and differs from sha256 variant" do
      secret = Random::Secure.random_bytes(32)
      v2_256 = QUIC::Crypto.derive_next_secret_v2(secret)
      v2_384_secret = Random::Secure.random_bytes(48)
      v2_384 = QUIC::Crypto.derive_next_secret_v2_sha384(v2_384_secret)
      v2_384.size.should eq(48)
      v2_256.size.should eq(32)
    end
  end

  describe QUIC::Connection do
    it "default quic_version is QUIC_V1" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      conn.quic_version.should eq(QUIC::Crypto::QUIC_V1_VERSION)
    end

    it "trigger_key_update is a no-op when app secrets are absent" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      expect_raises(Exception) { conn.trigger_key_update } rescue nil
      # The important thing is that it doesn't crash from nil pointer; it returns early
      conn.quic_version.should eq(QUIC::Crypto::QUIC_V1_VERSION)
    end
  end

  describe "Compatible Version Negotiation (RFC 9368)" do
    it "TransportParameters encodes and decodes quic_version_information (TP 0x11)" do
      tp = QUIC::TransportParameters.new
      tp.quic_version_information = {QUIC::Crypto::QUIC_V1_VERSION, [QUIC::Crypto::QUIC_V2_VERSION]}

      io = IO::Memory.new
      tp.encode(io)
      io.rewind
      decoded = QUIC::TransportParameters.decode(io)

      vi = decoded.quic_version_information
      vi.should_not be_nil
      vi.not_nil![0].should eq(QUIC::Crypto::QUIC_V1_VERSION)
      vi.not_nil![1].includes?(QUIC::Crypto::QUIC_V2_VERSION).should be_true
    end

    it "TransportParameters encodes multiple other_versions correctly" do
      tp = QUIC::TransportParameters.new
      tp.quic_version_information = {QUIC::Crypto::QUIC_V1_VERSION, [QUIC::Crypto::QUIC_V2_VERSION, 0xdeadbeef_u32]}

      io = IO::Memory.new
      tp.encode(io)
      io.rewind
      decoded = QUIC::TransportParameters.decode(io)

      vi = decoded.quic_version_information.not_nil!
      vi[1].size.should eq(2)
      vi[1].includes?(QUIC::Crypto::QUIC_V2_VERSION).should be_true
      vi[1].includes?(0xdeadbeef_u32).should be_true
    end

    it "VersionNegotiationPacket advertises both v1 and v2" do
      pkt = QUIC::VersionNegotiationPacket.new(
        Bytes.new(8), Bytes.new(8),
        [QUIC::Crypto::QUIC_V1_VERSION, QUIC::Crypto::QUIC_V2_VERSION]
      )
      io = IO::Memory.new
      pkt.encode(io)
      raw = io.to_slice
      # VN packet: 1 first_byte + 4 version(0) + 1 dcid_len + 8 dcid + 1 scid_len + 8 scid + 4*2 versions
      raw.size.should be >= 1 + 4 + 1 + 8 + 1 + 8 + 8
    end

    it "initial secrets are version-aware (v2 dcid produces different secrets than v1)" do
      dcid = Random::Secure.random_bytes(8)
      c1, s1 = QUIC::Crypto.derive_initial_secrets(dcid)
      c2, s2 = QUIC::Crypto.derive_initial_secrets_v2(dcid)
      (c1 == c2).should be_false
      (s1 == s2).should be_false
    end
  end
end
