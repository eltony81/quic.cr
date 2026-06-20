require "openssl"

lib LibSSL
  enum OSSL_ENCRYPTION_LEVEL
    INITIAL = 0
    EARLY_DATA = 1
    HANDSHAKE = 2
    APPLICATION = 3
  end

  alias SetEncryptionSecretsFn = (SSL, OSSL_ENCRYPTION_LEVEL, UInt8*, UInt8*, LibC::SizeT) -> Int32
  alias AddHandshakeDataFn = (SSL, OSSL_ENCRYPTION_LEVEL, UInt8*, LibC::SizeT) -> Int32
  alias FlushFlightFn = (SSL) -> Int32
  alias SendAlertFn = (SSL, OSSL_ENCRYPTION_LEVEL, UInt8) -> Int32

  struct SSL_QUIC_METHOD
    set_encryption_secrets : SetEncryptionSecretsFn
    add_handshake_data : AddHandshakeDataFn
    flush_flight : FlushFlightFn
    send_alert : SendAlertFn
  end

  fun SSL_set_quic_method(ssl : SSL, meth : SSL_QUIC_METHOD*) : Int32
  fun SSL_provide_quic_data(ssl : SSL, level : OSSL_ENCRYPTION_LEVEL, data : UInt8*, len : LibC::SizeT) : Int32
  fun SSL_is_init_finished(ssl : SSL) : Int32
  fun SSL_set_accept_state(ssl : SSL)
  fun SSL_set_connect_state(ssl : SSL)
  fun SSL_do_handshake(ssl : SSL) : Int32
  fun SSL_set_quic_tls_transport_params(ssl : SSL, params : UInt8*, params_len : LibC::SizeT) : Int32
  fun SSL_CTX_free(ctx : SSLContext) : Void
  fun SSL_free(ssl : SSL) : Void
end

lib LibCrypto
  fun ERR_get_error : UInt64
  fun ERR_error_string_n(e : UInt64, buf : UInt8*, len : LibC::SizeT) : Void
end

meth = LibSSL::SSL_QUIC_METHOD.new

meth.set_encryption_secrets = ->(ssl : LibSSL::SSL, level : LibSSL::OSSL_ENCRYPTION_LEVEL, read_secret : UInt8*, write_secret : UInt8*, secret_len : LibC::SizeT) : Int32 {
  puts "set_encryption_secrets_cb level=#{level} secret_len=#{secret_len}"
  1
}

meth.add_handshake_data = ->(ssl : LibSSL::SSL, level : LibSSL::OSSL_ENCRYPTION_LEVEL, data : UInt8*, len : LibC::SizeT) : Int32 {
  bytes = Bytes.new(data, len)
  puts "add_handshake_data_cb level=#{level} len=#{len} prefix=#{bytes[0, Math.min(10, len)].inspect}"
  1
}

meth.flush_flight = ->(ssl : LibSSL::SSL) : Int32 {
  puts "flush_flight_cb called"
  1
}

meth.send_alert = ->(ssl : LibSSL::SSL, level : LibSSL::OSSL_ENCRYPTION_LEVEL, alert : UInt8) : Int32 {
  puts "send_alert_cb level=#{level} alert=#{alert}"
  1
}

def print_errors(label)
  while (err_code = LibCrypto.ERR_get_error) != 0
    buf = Bytes.new(256)
    LibCrypto.ERR_error_string_n(err_code, buf, buf.size.to_u64)
    puts "[#{label}] OpenSSL error: #{String.new(buf).strip(0.chr)}"
  end
end

puts "Creating server context..."
server_ctx = LibSSL.ssl_ctx_new(LibSSL.tls_method)
LibSSL.ssl_ctx_ctrl(server_ctx, 123, 0x0304, nil) # min version
LibSSL.ssl_ctx_ctrl(server_ctx, 124, 0x0304, nil) # max version
LibSSL.ssl_ctx_use_certificate_chain_file(server_ctx, "cert.pem")
LibSSL.ssl_ctx_use_privatekey_file(server_ctx, "key.pem", LibSSL::SSLFileType::PEM)

server_ssl = LibSSL.ssl_new(server_ctx)
LibSSL.SSL_set_accept_state(server_ssl)

puts "Setting quic method..."
res = LibSSL.SSL_set_quic_method(server_ssl, pointerof(meth))
puts "SSL_set_quic_method returned #{res}"
print_errors("server")

puts "Setting transport params..."
tp = Bytes[1, 2, 3, 4]
res = LibSSL.SSL_set_quic_tls_transport_params(server_ssl, tp, tp.size.to_u64)
puts "SSL_set_quic_tls_transport_params returned #{res}"
print_errors("server")
