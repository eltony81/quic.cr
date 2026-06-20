require "openssl"
require "openssl/hmac"

# Raw libcrypto bindings used only by retry_integrity_tag.
# Crystal's OpenSSL::Cipher wrapper skips EVP_EncryptUpdate when the plaintext
# is empty, which leaves AES-GCM in AAD-only mode and produces a wrong tag.
# Calling the OpenSSL functions directly avoids that issue.
lib LibAesGcm
  fun evp_aes_128_gcm = EVP_aes_128_gcm() : Void*
  fun evp_cipher_ctx_new = EVP_CIPHER_CTX_new() : Void*
  fun evp_cipher_ctx_free = EVP_CIPHER_CTX_free(ctx : Void*) : Void
  fun evp_encrypt_init_ex = EVP_EncryptInit_ex(ctx : Void*, cipher : Void*, impl : Void*, key : UInt8*, iv : UInt8*) : Int32
  fun evp_encrypt_update = EVP_EncryptUpdate(ctx : Void*, outb : UInt8*, outl : Int32*, inb : UInt8*, inl : Int32) : Int32
  fun evp_encrypt_final_ex = EVP_EncryptFinal_ex(ctx : Void*, outb : UInt8*, outl : Int32*) : Int32
  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : Void*, type_id : Int32, arg : Int32, ptr : Void*) : Int32
end

module QUIC
  module AddressValidation
    @@secret : Bytes = Random::Secure.random_bytes(32)

    # RFC 9001 Appendix A.4 — fixed key and nonce for Retry Integrity Tag.
    RETRY_INTEGRITY_KEY   = Bytes[0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                   0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e]
    RETRY_INTEGRITY_NONCE = Bytes[0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
                                   0x23, 0x98, 0x25, 0xbb]

    # Computes the 16-byte Retry Integrity Tag per RFC 9001 Section 5.8.
    # odcid             — original destination connection ID (DCID from client's first Initial)
    # retry_without_tag — Retry packet bytes with the trailing 16-byte tag omitted
    def self.retry_integrity_tag(odcid : Bytes, retry_without_tag : Bytes) : Bytes
      pseudo_retry = IO::Memory.new
      pseudo_retry.write_byte odcid.size.to_u8
      pseudo_retry.write odcid
      pseudo_retry.write retry_without_tag
      aad = pseudo_retry.to_slice

      ctx = LibAesGcm.evp_cipher_ctx_new
      raise "EVP_CIPHER_CTX_new failed" if ctx.null?
      begin
        # Two-step init: first select cipher, then supply key + IV.
        LibAesGcm.evp_encrypt_init_ex(ctx, LibAesGcm.evp_aes_128_gcm, nil, nil, nil)
        LibAesGcm.evp_encrypt_init_ex(ctx, nil, nil,
          RETRY_INTEGRITY_KEY.to_unsafe,
          RETRY_INTEGRITY_NONCE.to_unsafe)
        # Process AAD: null output pointer signals GCM AAD mode to OpenSSL.
        outl = 0_i32
        LibAesGcm.evp_encrypt_update(ctx, Pointer(UInt8).null, pointerof(outl), aad.to_unsafe, aad.size)
        # Finalize with empty plaintext.
        final_outl = 0_i32
        final_buf  = Bytes.new(16)
        LibAesGcm.evp_encrypt_final_ex(ctx, final_buf.to_unsafe, pointerof(final_outl))
        # Extract the 16-byte GCM authentication tag.
        tag = Bytes.new(16)
        LibAesGcm.evp_cipher_ctx_ctrl(ctx, 0x10, 16, tag.to_unsafe.as(Void*))
        tag
      ensure
        LibAesGcm.evp_cipher_ctx_free(ctx)
      end
    end

    # Returns true if the trailing 16-byte tag of retry_packet is valid for odcid.
    def self.verify_retry_integrity(odcid : Bytes, retry_packet : Bytes) : Bool
      return false if retry_packet.size < 16
      expected = retry_integrity_tag(odcid, retry_packet[0...-16])
      Crypto.constant_time_compare(retry_packet[-16..-1], expected)
    end

    # Generates a token for a given address and timestamp.
    def self.generate_token(address : String, timestamp : Time = Time.local) : Bytes
      data = IO::Memory.new
      data.write address.to_slice
      IO::ByteFormat::NetworkEndian.encode(timestamp.to_unix, data)
      
      # Use HMAC to sign the token
      signature = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, @@secret, data.to_slice)
      
      final = IO::Memory.new
      final.write data.to_slice
      final.write signature
      final.to_slice
    end

    # Validates a token against an address.
    def self.validate_token(token : Bytes, address : String, max_age : Time::Span = 1.hour) : Bool
      # Minimum size: address (variable) + 8 bytes timestamp + 32 bytes signature
      return false if token.size < 40
      
      data_size = token.size - 32
      data = token[0, data_size]
      signature = token[data_size, 32]
      
      # Check signature
      expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, @@secret, data)
      return false unless Crypto.constant_time_compare(signature, expected)
      
      # Check address and timestamp
      timestamp_unix = IO::ByteFormat::NetworkEndian.decode(Int64, data[data.size - 8, 8])
      timestamp = Time.unix(timestamp_unix)
      
      return false if Time.local - timestamp > max_age
      
      token_address = String.new(data[0, data.size - 8])
      token_address == address
    end

    # Generates a stateless reset token for a given DCID (RFC 9000 Section 10.3.1).
    # Uses HMAC-SHA256 keyed with the server secret so attackers cannot forge tokens.
    def self.stateless_reset_token(dcid : Bytes) : Bytes
      OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, @@secret, dcid)[0, 16]
    end
  end
end

module QUIC::Crypto
  def self.constant_time_compare(a : Bytes, b : Bytes) : Bool
    return false if a.size != b.size
    res = 0_u8
    a.size.times do |i|
      res |= a[i] ^ b[i]
    end
    res == 0
  end
end
