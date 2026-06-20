require "./spec_helper"

describe "QUIC::AddressValidation" do
  describe "generate_token / validate_token" do
    it "validates a token for the correct address" do
      token = QUIC::AddressValidation.generate_token("192.168.1.1")
      QUIC::AddressValidation.validate_token(token, "192.168.1.1").should be_true
    end

    it "rejects a token presented for a different address" do
      token = QUIC::AddressValidation.generate_token("192.168.1.1")
      QUIC::AddressValidation.validate_token(token, "10.0.0.1").should be_false
    end

    it "rejects a token that has exceeded max_age" do
      past = Time.local - 2.hours
      token = QUIC::AddressValidation.generate_token("192.168.1.1", past)
      QUIC::AddressValidation.validate_token(token, "192.168.1.1", 1.hour).should be_false
    end

    it "accepts a fresh token within max_age" do
      token = QUIC::AddressValidation.generate_token("10.0.0.1")
      QUIC::AddressValidation.validate_token(token, "10.0.0.1", 1.hour).should be_true
    end

    it "rejects a token shorter than the minimum size" do
      QUIC::AddressValidation.validate_token(Bytes.new(10), "1.2.3.4").should be_false
    end

    it "rejects a token with a corrupted HMAC signature" do
      token = QUIC::AddressValidation.generate_token("1.2.3.4").dup
      token[0] ^= 0xff_u8  # flip bits in the address portion
      QUIC::AddressValidation.validate_token(token, "1.2.3.4").should be_false
    end

    it "rejects a token with a corrupted timestamp" do
      token = QUIC::AddressValidation.generate_token("1.2.3.4").dup
      # Timestamp is the 8 bytes immediately before the 32-byte HMAC at the end
      ts_offset = token.size - 32 - 8
      token[ts_offset] ^= 0xff_u8
      QUIC::AddressValidation.validate_token(token, "1.2.3.4").should be_false
    end
  end

  describe "stateless_reset_token" do
    it "returns exactly 16 bytes" do
      QUIC::AddressValidation.stateless_reset_token(Bytes.new(8, 1)).size.should eq(16)
    end

    it "is deterministic for the same DCID within a server lifetime" do
      dcid = Bytes.new(8, 42)
      t1 = QUIC::AddressValidation.stateless_reset_token(dcid)
      t2 = QUIC::AddressValidation.stateless_reset_token(dcid)
      t1.should eq(t2)
    end

    it "produces different tokens for different DCIDs" do
      t1 = QUIC::AddressValidation.stateless_reset_token(Bytes.new(8, 1))
      t2 = QUIC::AddressValidation.stateless_reset_token(Bytes.new(8, 2))
      t1.should_not eq(t2)
    end
  end

  describe "retry_integrity_tag" do
    # Test vector cross-checked against aioquic and Python cryptography:
    #   ODCID (from Appendix A.2 Initial): 8394c8f03e515708
    #   Retry without tag:  ff000000010008f067a5502a4262b5746f6b656e
    #   Key:   be0c690b9f66575a1d766b54e368c84e  (RFC 9001 §5.8)
    #   Nonce: 461599d35d632bf2239825bb          (RFC 9001 §5.8)
    #   Tag (verified with aioquic): 04a265ba2eff4d829058fb3f0f2496ba
    it "matches the cross-validated tag for the RFC 9001 §5.8 inputs" do
      odcid = Bytes[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]

      retry_without_tag = Bytes[
        0xff, 0x00, 0x00, 0x00, 0x01, # first byte + version
        0x00,                          # DCID length = 0
        0x08,                          # SCID length = 8
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, # SCID
        0x74, 0x6f, 0x6b, 0x65, 0x6e  # token = "token"
      ]

      # Verified with both aioquic and Python cryptography AESGCM
      expected_tag = Bytes[
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba
      ]

      tag = QUIC::AddressValidation.retry_integrity_tag(odcid, retry_without_tag)
      tag.should eq(expected_tag)
    end

    it "verify_retry_integrity returns true for the cross-validated test vector" do
      odcid = Bytes[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]

      retry_without_tag = Bytes[
        0xff, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x08,
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e
      ]
      tag = Bytes[
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba
      ]

      full_retry = Bytes.new(retry_without_tag.size + tag.size)
      retry_without_tag.copy_to(full_retry)
      tag.copy_to(full_retry + retry_without_tag.size)

      QUIC::AddressValidation.verify_retry_integrity(odcid, full_retry).should be_true
    end

    it "verify_retry_integrity returns false for a tampered tag" do
      odcid = Bytes[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]

      retry_without_tag = Bytes[
        0xff, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x08,
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e
      ]
      bad_tag = Bytes.new(16, 0_u8)  # all-zero tag is wrong

      full_retry = Bytes.new(retry_without_tag.size + bad_tag.size)
      retry_without_tag.copy_to(full_retry)
      bad_tag.copy_to(full_retry + retry_without_tag.size)

      QUIC::AddressValidation.verify_retry_integrity(odcid, full_retry).should be_false
    end

    it "verify_retry_integrity returns false when the ODCID does not match" do
      odcid       = Bytes[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
      wrong_odcid = Bytes.new(8, 0xff_u8)

      retry_without_tag = Bytes[
        0xff, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x08,
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e
      ]
      correct_tag = Bytes[
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba
      ]

      full_retry = Bytes.new(retry_without_tag.size + correct_tag.size)
      retry_without_tag.copy_to(full_retry)
      correct_tag.copy_to(full_retry + retry_without_tag.size)

      QUIC::AddressValidation.verify_retry_integrity(wrong_odcid, full_retry).should be_false
    end

    it "verify_retry_integrity returns false for a packet shorter than 16 bytes" do
      QUIC::AddressValidation.verify_retry_integrity(Bytes.new(8), Bytes.new(8)).should be_false
    end
  end

  describe "Retry round-trip (server generates, client verifies)" do
    it "produces a tag that verify_retry_integrity accepts" do
      odcid      = Random::Secure.random_bytes(8)
      client_scid = Random::Secure.random_bytes(8)
      retry_scid  = Random::Secure.random_bytes(8)
      addr_token  = QUIC::AddressValidation.generate_token("127.0.0.1")

      # Simulate server: build Retry without tag, compute tag, assemble
      partial = IO::Memory.new
      QUIC::RetryPacket.new(0x00000001_u32, client_scid, retry_scid, addr_token, Bytes.empty)
        .encode_without_tag(partial)
      tag = QUIC::AddressValidation.retry_integrity_tag(odcid, partial.to_slice)

      full = Bytes.new(partial.size + tag.size)
      partial.to_slice.copy_to(full)
      tag.copy_to(full + partial.size)

      # Simulate client: verify
      QUIC::AddressValidation.verify_retry_integrity(odcid, full).should be_true
    end

    it "client rejects a Retry with a different ODCID" do
      real_odcid  = Random::Secure.random_bytes(8)
      wrong_odcid = Random::Secure.random_bytes(8)
      client_scid  = Random::Secure.random_bytes(8)
      retry_scid   = Random::Secure.random_bytes(8)
      addr_token   = QUIC::AddressValidation.generate_token("127.0.0.1")

      partial = IO::Memory.new
      QUIC::RetryPacket.new(0x00000001_u32, client_scid, retry_scid, addr_token, Bytes.empty)
        .encode_without_tag(partial)
      tag = QUIC::AddressValidation.retry_integrity_tag(real_odcid, partial.to_slice)

      full = Bytes.new(partial.size + tag.size)
      partial.to_slice.copy_to(full)
      tag.copy_to(full + partial.size)

      QUIC::AddressValidation.verify_retry_integrity(wrong_odcid, full).should be_false
    end
  end
end
