require "openssl"

module QUIC
  module AddressValidation
    @@secret : Bytes = Random::Secure.random_bytes(32)
    
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

    # Generates a stateless reset token for a given DCID
    def self.stateless_reset_token(dcid : Bytes) : Bytes
      salt = "stateless-reset-salt".to_slice
      concat = Bytes.new(dcid.size + salt.size)
      concat[0, dcid.size].copy_from(dcid)
      concat[dcid.size, salt.size].copy_from(salt)
      
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(concat)
      digest.final[0, 16]
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
