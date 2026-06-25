require "./spec_helper"

describe "Stateless Reset (RFC 9000 §10.3)" do
  describe QUIC::AddressValidation do
    it "stateless_reset_token returns a 16-byte token" do
      dcid  = Random::Secure.random_bytes(8)
      token = QUIC::AddressValidation.stateless_reset_token(dcid)
      token.size.should eq(16)
    end

    it "token is deterministic for the same DCID" do
      dcid   = Bytes[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
      token1 = QUIC::AddressValidation.stateless_reset_token(dcid)
      token2 = QUIC::AddressValidation.stateless_reset_token(dcid)
      token1.should eq(token2)
    end

    it "token differs for different DCIDs" do
      t1 = QUIC::AddressValidation.stateless_reset_token(Bytes[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
      t2 = QUIC::AddressValidation.stateless_reset_token(Bytes[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
      t1.should_not eq(t2)
    end
  end

  describe "Stateless Reset packet format" do
    it "is 40 bytes, short-header (bit7=0), fixed-bit (bit6=1), token at offset 24" do
      dcid  = Bytes[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]
      token = QUIC::AddressValidation.stateless_reset_token(dcid)

      reset_pkt = Bytes.new(40)
      reset_pkt[0] = 0x40_u8 | Random::Secure.rand(64).to_u8
      Random::Secure.random_bytes(reset_pkt[1, 23])
      reset_pkt[24, 16].copy_from(token)

      reset_pkt.size.should eq(40)
      (reset_pkt[0] & 0x80_u8).should eq(0_u8)    # short header
      (reset_pkt[0] & 0x40_u8).should eq(0x40_u8) # fixed bit
      reset_pkt[24, 16].should eq(token)            # token at wire offset 24
    end

    it "client detects reset: last 16 bytes match the expected token (RFC 9000 §10.3.1)" do
      dcid  = Bytes[0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef]
      token = QUIC::AddressValidation.stateless_reset_token(dcid)

      reset_pkt = Bytes.new(40)
      reset_pkt[24, 16].copy_from(token)

      tail = reset_pkt[-16..-1]
      QUIC::Crypto.constant_time_compare(tail, token).should be_true
    end

    it "random prefix does not match the token (constant_time_compare rejects)" do
      dcid  = Bytes[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
      token = QUIC::AddressValidation.stateless_reset_token(dcid)
      noise = Random::Secure.random_bytes(16)
      QUIC::Crypto.constant_time_compare(noise, token).should be_false
    end
  end
end
