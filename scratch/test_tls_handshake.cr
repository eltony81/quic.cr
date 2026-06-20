require "openssl"

lib LibSSL
  TLS1_3_VERSION = 0x0304
  SSL_CTRL_SET_MIN_PROTO_VERSION = 123
  SSL_CTRL_SET_MAX_PROTO_VERSION = 124
  SSL_EXT_CLIENT_HELLO = 0x0001
  SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS = 0x0200

  fun SSL_is_init_finished(ssl : SSL) : Int32
  fun SSL_set_accept_state(ssl : SSL)
  fun SSL_set_connect_state(ssl : SSL)
  fun SSL_do_handshake(ssl : SSL) : Int32
  fun SSL_set_alpn_protos(ssl : SSL, protos : UInt8*, protos_len : LibC::UInt) : Int32
  fun ssl_ctx_set_alpn_select_cb = SSL_CTX_set_alpn_select_cb(ctx : SSLContext, cb : (SSL, UInt8**, UInt8*, UInt8*, Int32, Void*) -> Int32, arg : Void*) : Void
  fun SSL_CTX_free(ctx : SSLContext) : Void
  fun SSL_free(ssl : SSL) : Void

  alias SSL_custom_ext_add_cb_ex = (SSL, LibC::UInt, LibC::UInt, UInt8**, LibC::SizeT*, Void*, LibC::SizeT, Int32*, Void*) -> Int32
  alias SSL_custom_ext_free_cb_ex = (SSL, LibC::UInt, LibC::UInt, UInt8*, Void*) -> Void
  alias SSL_custom_ext_parse_cb_ex = (SSL, LibC::UInt, LibC::UInt, UInt8*, LibC::SizeT, Void*, LibC::SizeT, Int32*, Void*) -> Int32
  fun SSL_CTX_add_custom_ext(ctx : SSLContext, ext_type : LibC::UInt, context : LibC::UInt, add_cb : SSL_custom_ext_add_cb_ex, free_cb : SSL_custom_ext_free_cb_ex, add_arg : Void*, parse_cb : SSL_custom_ext_parse_cb_ex, parse_arg : Void*) : Int32
end

lib LibCrypto
  fun BIO_s_mem : BioMethod*
  fun BIO_new(method : BioMethod*) : Bio*
  fun BIO_write(bio : Bio*, data : UInt8*, len : Int32) : Int32
  fun BIO_read(bio : Bio*, data : UInt8*, len : Int32) : Int32
  fun BIO_ctrl_pending(bio : Bio*) : Int32
  fun ERR_get_error : UInt64
  fun ERR_error_string_n(e : UInt64, buf : UInt8*, len : LibC::SizeT) : Void
end

class DummyTLS
  getter local_encoded_tp : Bytes = Bytes[1, 2, 3, 4]
end

def self.tp_add_cb(ssl : LibSSL::SSL, ext_type : LibC::UInt, context : LibC::UInt, out_ptr : UInt8**, outlen : LibC::SizeT*, x : Void*, chainidx : LibC::SizeT, al : Int32*, add_arg : Void*) : Int32
  puts "tp_add_cb called!"
  this = Box(DummyTLS).unbox(add_arg)
  out_ptr.value = this.local_encoded_tp.to_unsafe
  outlen.value = this.local_encoded_tp.size.to_u64
  1
end

def self.tp_free_cb(ssl : LibSSL::SSL, ext_type : LibC::UInt, context : LibC::UInt, out_ptr : UInt8*, add_arg : Void*) : Void
end

def self.tp_parse_cb(ssl : LibSSL::SSL, ext_type : LibC::UInt, context : LibC::UInt, in_ptr : UInt8*, inlen : LibC::SizeT, x : Void*, chainidx : LibC::SizeT, al : Int32*, parse_arg : Void*) : Int32
  puts "tp_parse_cb called! inlen=#{inlen}"
  1
end

def self.alpn_select_cb(ssl : LibSSL::SSL, out_ptr : UInt8**, outlen : UInt8*, in_ptr : UInt8*, inlen : Int32, arg : Void*) : Int32
  puts "alpn_select_cb called! inlen=#{inlen}"
  i = 0
  while i < inlen
    len = in_ptr[i]
    proto = String.new(in_ptr + i + 1, len)
    puts "  Offered ALPN: #{proto}"
    if proto == "h3"
      out_ptr.value = in_ptr + i + 1
      outlen.value = len
      return 0
    end
    i += 1 + len
  end
  3
end

def print_errors(label)
  while (err_code = LibCrypto.ERR_get_error) != 0
    buf = Bytes.new(256)
    LibCrypto.ERR_error_string_n(err_code, buf, buf.size.to_u64)
    puts "[#{label}] OpenSSL error: #{String.new(buf).strip(0.chr)}"
  end
end

puts "Creating contexts..."
server_ctx = LibSSL.ssl_ctx_new(LibSSL.tls_method)
LibSSL.ssl_ctx_ctrl(server_ctx, LibSSL::SSL_CTRL_SET_MIN_PROTO_VERSION, LibSSL::TLS1_3_VERSION, nil)
LibSSL.ssl_ctx_ctrl(server_ctx, LibSSL::SSL_CTRL_SET_MAX_PROTO_VERSION, LibSSL::TLS1_3_VERSION, nil)

client_ctx = LibSSL.ssl_ctx_new(LibSSL.tls_method)
LibSSL.ssl_ctx_ctrl(client_ctx, LibSSL::SSL_CTRL_SET_MIN_PROTO_VERSION, LibSSL::TLS1_3_VERSION, nil)
LibSSL.ssl_ctx_ctrl(client_ctx, LibSSL::SSL_CTRL_SET_MAX_PROTO_VERSION, LibSSL::TLS1_3_VERSION, nil)

puts "Loading Server Cert and Key..."
LibSSL.ssl_ctx_use_certificate_chain_file(server_ctx, "cert.pem")
LibSSL.ssl_ctx_use_privatekey_file(server_ctx, "key.pem", LibSSL::SSLFileType::PEM)

ext_context = LibSSL::SSL_EXT_CLIENT_HELLO | LibSSL::SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS

dummy = DummyTLS.new
box_ptr = Box.box(dummy)

LibSSL.SSL_CTX_add_custom_ext(server_ctx, 57_u32, ext_context, ->tp_add_cb, ->tp_free_cb, box_ptr, ->tp_parse_cb, box_ptr)
LibSSL.ssl_ctx_set_alpn_select_cb(server_ctx, ->alpn_select_cb, nil)

LibSSL.SSL_CTX_add_custom_ext(client_ctx, 57_u32, ext_context, ->tp_add_cb, ->tp_free_cb, box_ptr, ->tp_parse_cb, box_ptr)

client_ssl = LibSSL.ssl_new(client_ctx)
server_ssl = LibSSL.ssl_new(server_ctx)

LibSSL.SSL_set_connect_state(client_ssl)
LibSSL.SSL_set_accept_state(server_ssl)

alpn = Bytes[0x02, 0x68, 0x33] # "\x02h3"
LibSSL.SSL_set_alpn_protos(client_ssl, alpn, alpn.size)

c_read_bio = LibCrypto.BIO_new(LibCrypto.BIO_s_mem)
c_write_bio = LibCrypto.BIO_new(LibCrypto.BIO_s_mem)
LibSSL.ssl_set_bio(client_ssl, c_read_bio, c_write_bio)

s_read_bio = LibCrypto.BIO_new(LibCrypto.BIO_s_mem)
s_write_bio = LibCrypto.BIO_new(LibCrypto.BIO_s_mem)
LibSSL.ssl_set_bio(server_ssl, s_read_bio, s_write_bio)

puts "Starting Handshake Loop..."
iter = 0
while iter < 20
  iter += 1
  puts "\n--- Iteration #{iter} ---"
  
  # Client -> Server
  c_pending = LibCrypto.BIO_ctrl_pending(c_write_bio)
  if c_pending > 0
    buf = Bytes.new(c_pending)
    LibCrypto.BIO_read(c_write_bio, buf, c_pending)
    LibCrypto.BIO_write(s_read_bio, buf, buf.size)
    puts "Fed #{buf.size} bytes from Client to Server"
  end
  
  # Server -> Client
  s_pending = LibCrypto.BIO_ctrl_pending(s_write_bio)
  if s_pending > 0
    buf = Bytes.new(s_pending)
    LibCrypto.BIO_read(s_write_bio, buf, s_pending)
    LibCrypto.BIO_write(c_read_bio, buf, buf.size)
    puts "Fed #{buf.size} bytes from Server to Client"
  end
  
  c_ret = LibSSL.SSL_do_handshake(client_ssl)
  s_ret = LibSSL.SSL_do_handshake(server_ssl)
  
  c_finished = LibSSL.SSL_is_init_finished(client_ssl) == 1
  s_finished = LibSSL.SSL_is_init_finished(server_ssl) == 1
  
  puts "Client handshake ret: #{c_ret}, finished? #{c_finished}"
  print_errors("Client")
  puts "Server handshake ret: #{s_ret}, finished? #{s_finished}"
  print_errors("Server")
  
  break if c_finished && s_finished
end

