require "openssl"
require "openssl/hmac"

# Extend LibCrypto with missing GCM control functions
lib LibCrypto
  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : Int32, arg : Int32, ptr : Void*) : Int32
  EVP_CTRL_GCM_GET_TAG = 0x10
  EVP_CTRL_GCM_SET_TAG = 0x11
end

# Extend OpenSSL::Cipher with AEAD support
class OpenSSL::Cipher
  def update_ad(data)
    slice = data.to_slice
    if LibCrypto.evp_cipherupdate(@ctx, nil, out out_len, slice, slice.size) != 1
      raise Error.new "EVP_CipherUpdate (AD)"
    end
    nil
  end

  def gcm_get_tag : Bytes
    tag = Bytes.new(16)
    if LibCrypto.evp_cipher_ctx_ctrl(@ctx, LibCrypto::EVP_CTRL_GCM_GET_TAG, 16, tag) != 1
      raise Error.new "EVP_CIPHER_CTX_ctrl (GET_TAG)"
    end
    tag
  end

  def gcm_set_tag(tag : Bytes)
    if LibCrypto.evp_cipher_ctx_ctrl(@ctx, LibCrypto::EVP_CTRL_GCM_SET_TAG, tag.size, tag.to_unsafe) != 1
      raise Error.new "EVP_CIPHER_CTX_ctrl (SET_TAG)"
    end
  end
end

module QUIC
  module Crypto
    INITIAL_SALT_V1 = Bytes[0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]

    class AEAD
      @key : Bytes
      @iv : Bytes

      def initialize(@key, @iv)
      end

      def encrypt(ad : Bytes, pn : UInt64, plaintext : Bytes) : Bytes
        nonce = build_nonce(pn)
        cipher = OpenSSL::Cipher.new("AES-128-GCM")
        cipher.encrypt
        cipher.key = @key
        cipher.iv = nonce
        cipher.update_ad(ad)
        
        ciphertext = cipher.update(plaintext)
        ciphertext += cipher.final
        
        tag = cipher.gcm_get_tag
        ciphertext + tag
      end

      def decrypt(ad : Bytes, pn : UInt64, ciphertext : Bytes) : Bytes
        nonce = build_nonce(pn)
        tag_size = 16
        raise Error.new("Ciphertext too short") if ciphertext.size < tag_size
        
        actual_ciphertext = ciphertext[0...-tag_size]
        tag = ciphertext[-tag_size..-1]

        cipher = OpenSSL::Cipher.new("AES-128-GCM")
        cipher.decrypt
        cipher.key = @key
        cipher.iv = nonce
        cipher.update_ad(ad)
        cipher.gcm_set_tag(tag)
        
        plaintext = cipher.update(actual_ciphertext)
        plaintext + cipher.final
      rescue e : OpenSSL::Cipher::Error
        raise InternalError.new("Decryption failed: #{e.message}")
      end

      private def build_nonce(pn : UInt64) : Bytes
        nonce = @iv.dup
        (0..7).each do |i|
          idx = nonce.size - 1 - i
          val = ((pn >> (i * 8)) & 0xff).to_u8
          nonce[idx] ^= val
        end
        nonce
      end
    end

    def self.hkdf_extract(salt : Bytes, ikm : Bytes) : Bytes
      OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, salt, ikm)
    end

    def self.hkdf_expand_label(secret : Bytes, label : String, context : Bytes, length : Int) : Bytes
      full_label = "tls13 #{label}"
      info = IO::Memory.new
      IO::ByteFormat::NetworkEndian.encode(length.to_u16, info)
      info.write_byte(full_label.size.to_u8)
      info.write(full_label.to_slice)
      info.write_byte(context.size.to_u8)
      info.write(context)
      hkdf_expand(secret, info.to_slice, length)
    end

    def self.hkdf_expand(secret : Bytes, info : Bytes, length : Int) : Bytes
      okm = Bytes.new(length)
      n = (length.to_f / 32).ceil.to_i
      t = Bytes.empty
      pos = 0
      (1..n).each do |i|
        ctx = IO::Memory.new
        ctx.write(t)
        ctx.write(info)
        ctx.write_byte(i.to_u8)
        t = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, secret, ctx.to_slice)
        copy_len = Math.min(32, length - pos)
        okm[pos, copy_len].copy_from(t[0, copy_len])
        pos += copy_len
      end
      okm
    end

    def self.derive_initial_secrets(dcid : Bytes)
      initial_secret = hkdf_extract(INITIAL_SALT_V1, dcid)
      client_initial_secret = hkdf_expand_label(initial_secret, "client in", Bytes.empty, 32)
      server_initial_secret = hkdf_expand_label(initial_secret, "server in", Bytes.empty, 32)
      {client_initial_secret, server_initial_secret}
    end

    def self.derive_next_secret(secret : Bytes) : Bytes
      hkdf_expand_label(secret, "ku", Bytes.empty, 32)
    end

    class HeaderProtection
      @key : Bytes

      def initialize(@key)
      end

      def mask(sample : Bytes) : Bytes
        cipher = OpenSSL::Cipher.new("AES-128-ECB")
        cipher.encrypt
        cipher.key = @key
        cipher.padding = false
        mask = cipher.update(sample)
        mask + cipher.final
      end

      def apply!(header : Bytes, pn_offset : Int, mask : Bytes, unprotect : Bool)
        is_long = (header[0] & 0x80) != 0
        if unprotect
          header[0] ^= mask[0] & (is_long ? 0x0f : 0x1f)
          pn_len = (header[0] & 0x03) + 1
        else
          pn_len = (header[0] & 0x03) + 1
          header[0] ^= mask[0] & (is_long ? 0x0f : 0x1f)
        end
        (0...pn_len).each do |i|
          header[pn_offset + i] ^= mask[1 + i]
        end
      end
    end

    def self.encrypt_tls_record(secret : Bytes, seq_num : UInt64, plaintext : Bytes, inner_type : UInt8) : Bytes
      key = hkdf_expand_label(secret, "key", Bytes.empty, 16)
      iv  = hkdf_expand_label(secret, "iv", Bytes.empty, 12)
      
      nonce = iv.dup
      (0..7).each do |i|
        idx = nonce.size - 1 - i
        val = ((seq_num >> (i * 8)) & 0xff).to_u8
        nonce[idx] ^= val
      end
      
      inner_plaintext = Bytes.new(plaintext.size + 1)
      plaintext.copy_to(inner_plaintext)
      inner_plaintext[plaintext.size] = inner_type
      
      rec_len = inner_plaintext.size + 16
      
      record = Bytes.new(5 + rec_len)
      record[0] = 23_u8
      record[1] = 3_u8
      record[2] = 3_u8
      record[3] = (rec_len >> 8).to_u8
      record[4] = (rec_len & 0xff).to_u8
      
      ad = record[0...5]
      
      cipher = OpenSSL::Cipher.new("AES-128-GCM")
      cipher.encrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.update_ad(ad)
      
      ciphertext = cipher.update(inner_plaintext) + cipher.final
      tag = cipher.gcm_get_tag
      
      ciphertext.copy_to(record[5, ciphertext.size])
      tag.copy_to(record[5 + ciphertext.size, tag.size])
      
      record
    end

    def self.decrypt_tls_record(secret : Bytes, seq_num : UInt64, record : Bytes) : {Bytes, UInt8}
      raise "Invalid record header" unless record.size >= 5 && record[0] == 23 && record[1] == 3 && record[2] == 3
      
      key = hkdf_expand_label(secret, "key", Bytes.empty, 16)
      iv  = hkdf_expand_label(secret, "iv", Bytes.empty, 12)
      
      nonce = iv.dup
      (0..7).each do |i|
        idx = nonce.size - 1 - i
        val = ((seq_num >> (i * 8)) & 0xff).to_u8
        nonce[idx] ^= val
      end
      
      ad = record[0...5]
      ciphertext = record[5..-1]
      
      tag_size = 16
      raise "Ciphertext too short" if ciphertext.size < tag_size
      
      actual_ciphertext = ciphertext[0...-tag_size]
      tag = ciphertext[-tag_size..-1]
      
      cipher = OpenSSL::Cipher.new("AES-128-GCM")
      cipher.decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.update_ad(ad)
      cipher.gcm_set_tag(tag)
      
      decrypted = cipher.update(actual_ciphertext) + cipher.final
      
      idx = decrypted.size - 1
      while idx >= 0 && decrypted[idx] == 0
        idx -= 1
      end
      raise "Malformed TLS record payload" if idx < 0
      inner_type = decrypted[idx]
      plaintext = decrypted[0...idx]
      
      {plaintext, inner_type}
    end
  end
end
