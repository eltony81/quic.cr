require "./spec_helper"

describe QUIC::Crypto do
  it "derives initial secrets (smoke test)" do
    dcid = Bytes[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
    client_secret, server_secret = QUIC::Crypto.derive_initial_secrets(dcid)
    client_secret.size.should eq(32)
    server_secret.size.should eq(32)
    client_secret.should_not eq(server_secret)
  end

  it "encrypts and decrypts with AEAD" do
    key = Bytes.new(16, 0x01)
    iv = Bytes.new(12, 0x02)
    aead = QUIC::Crypto::AEAD.new(key, iv)
    
    ad = Bytes[0x01, 0x02, 0x03]
    pn = 12345_u64
    plaintext = "Hello QUIC".to_slice
    
    ciphertext = aead.encrypt(ad, pn, plaintext)
    ciphertext.size.should eq(plaintext.size + 16) # 16 byte tag
    
    decrypted = aead.decrypt(ad, pn, ciphertext)
    decrypted.should eq(plaintext)
  end
end
