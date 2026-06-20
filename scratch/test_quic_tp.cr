require "../src/quic"

method = LibSSL.tls_method
ctx = LibSSL.ssl_ctx_new(method)

# Try adding custom extension 57 using the callbacks in QUIC
ret = LibSSL.SSL_CTX_add_custom_ext(
  ctx,
  57_u32,
  LibSSL::SSL_EXT_CLIENT_HELLO | LibSSL::SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
  ->QUIC.tp_add_cb,
  ->QUIC.tp_free_cb,
  nil,
  ->QUIC.tp_parse_cb,
  nil
)

puts "SSL_CTX_add_custom_ext returned: #{ret}"

if ret == 0
  while (err_code = LibCrypto.ERR_get_error) != 0
    buf = Bytes.new(256)
    LibCrypto.ERR_error_string_n(err_code, buf, buf.size.to_u64)
    puts "OpenSSL Error: #{String.new(buf).strip(0.chr)}"
  end
end

LibSSL.SSL_CTX_free(ctx)
