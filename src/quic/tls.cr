require "openssl"

module QUIC
  # Static callbacks for LibSSL
  def self.crypto_send_cb(ssl : LibSSL::SSL, buf : UInt8*, buf_len : LibC::SizeT, consumed : LibC::SizeT*, arg : Void*) : Int32
    this = Box(TLS).unbox(arg)
    slice = Bytes.new(buf, buf_len)
    Log.trace { "TLS: crypto_send_cb len=#{buf_len} byte0=#{buf[0].to_s(16)}" }
    this.append_send_buf(slice)
    consumed.value = buf_len
    1
  end

  def self.crypto_recv_rcd_cb(ssl : LibSSL::SSL, buf_ptr : UInt8**, bytes_read : LibC::SizeT*, arg : Void*) : Int32
    this = Box(TLS).unbox(arg)
    if recv = this.recv_buf
      buf_ptr.value = recv.to_unsafe
      bytes_read.value = recv.size.to_u64
      Log.trace { "TLS: crypto_recv_rcd_cb providing #{recv.size} bytes" }
      1
    else
      Log.trace { "TLS: crypto_recv_rcd_cb providing 0 bytes" }
      bytes_read.value = 0_u64
      1
    end
  end

  def self.crypto_release_rcd_cb(ssl : LibSSL::SSL, bytes_read : LibC::SizeT, arg : Void*) : Int32
    this = Box(TLS).unbox(arg)
    if recv = this.recv_buf
      Log.trace { "TLS: crypto_release_rcd_cb consumed #{bytes_read} bytes out of #{recv.size}" }
      if bytes_read >= recv.size
        this.recv_buf = nil
      else
        new_buf = Bytes.new(recv.size - bytes_read)
        recv[bytes_read, new_buf.size].copy_to(new_buf)
        this.recv_buf = new_buf
      end
    else
      Log.trace { "TLS: crypto_release_rcd_cb called with no recv_buf!" }
    end
    1
  end

  def self.yield_secret_cb(ssl : LibSSL::SSL, prot_level : UInt32, direction : Int32, secret : UInt8*, secret_len : LibC::SizeT, arg : Void*) : Int32
    this = Box(TLS).unbox(arg)
    if direction == 1
      this.current_write_level = prot_level
    end
    1
  end

  def self.got_transport_params_cb(ssl : LibSSL::SSL, params : UInt8*, params_len : LibC::SizeT, arg : Void*) : Int32
    this = Box(TLS).unbox(arg)
    bytes = Bytes.new(params, params_len)
    Log.trace { "TLS Callback: got_transport_params_cb with #{params_len} bytes" }
    io = IO::Memory.new(bytes)
    tp = TransportParameters.decode(io)
    this.set_remote_tp(tp)
    1
  rescue ex
    Log.trace { "TLS Callback: got_transport_params_cb error: #{ex.message}" }
    0
  end

  def self.alert_cb(ssl : LibSSL::SSL, alert_code : UInt8, arg : Void*) : Int32
    Log.trace { "TLS ALERT: #{alert_code}" }
    1
  end

  def self.alpn_select_cb(ssl : LibSSL::SSL, out_ptr : LibC::Char**, outlen : LibC::Char*, in_ptr : LibC::Char*, inlen : LibC::Int, arg : Void*) : LibC::Int
    Log.trace { "TLS Callback: alpn_select_cb called with inlen=#{inlen}" }
    begin
      i = 0
      while i < inlen
        len = in_ptr[i]
        proto = String.new((in_ptr + i + 1).as(UInt8*), len)
        Log.trace { "  Offered ALPN: #{proto}" }
        if proto == "h3"
          out_ptr.value = in_ptr + i + 1
          outlen.value = len
          Log.trace { "  Selected ALPN: h3" }
          return 0
        end
        i += 1 + len
      end
      Log.trace { "  ALPN selection failed, returning no match" }
      3
    rescue ex
      Log.trace { "TLS Callback: alpn_select_cb raised exception: #{ex.message}" }
      3
    end
  end

  def self.keylog_cb(ssl : LibSSL::SSL, line : LibC::Char*) : Void
    begin
      ptr = LibSSL.SSL_get_ex_data(ssl, 0)
      return if ptr.null?
      this = Box(TLS).unbox(ptr)
      this.process_keylog_line(String.new(line))
    rescue ex
      Log.trace { "TLS Callback: keylog_cb raised exception: #{ex.message}" }
    end
  end

  class TLS
    @ssl : LibSSL::SSL = Pointer(Void).null.as(LibSSL::SSL)
    @ssl_ctx : LibSSL::SSLContext = Pointer(Void).null.as(LibSSL::SSLContext)
    property recv_buf : Bytes? = nil
    getter send_buf_initial : IO::Memory = IO::Memory.new
    getter send_buf_handshake : IO::Memory = IO::Memory.new
    getter send_buf_app : IO::Memory = IO::Memory.new
    property current_write_level : UInt32 = LibSSL::OSSL_RECORD_PROTECTION_LEVEL_NONE
    @dispatch : Pointer(LibSSL::OSSL_DISPATCH) = Pointer(LibSSL::OSSL_DISPATCH).null

    def append_send_buf(slice : Bytes)
      pos = 0
      while pos < slice.size
        msg_type = slice[pos]
        if pos + 3 >= slice.size
          route_msg(msg_type, slice[pos, slice.size - pos])
          break
        end
        msg_len = (slice[pos + 1].to_u32 << 16) | (slice[pos + 2].to_u32 << 8) | slice[pos + 3].to_u32
        total_len = 4 + msg_len
        if pos + total_len > slice.size
          route_msg(msg_type, slice[pos, slice.size - pos])
          break
        end
        route_msg(msg_type, slice[pos, total_len])
        pos += total_len
      end
    end

    def route_msg(msg_type : UInt8, slice : Bytes)
      if msg_type == 1_u8 || msg_type == 2_u8 # ClientHello, ServerHello
        @send_buf_initial.write(slice)
      elsif msg_type == 4_u8 || msg_type == 24_u8 # NewSessionTicket, KeyUpdate
        @send_buf_app.write(slice)
      else
        @send_buf_handshake.write(slice)
      end
    end

    def clear_recv_buf
      @recv_buf = nil
    end

    getter remote_transport_parameters : TransportParameters?
    getter local_encoded_tp : Bytes?
    getter is_server : Bool
    property on_secret : Proc(String, Bytes, Nil)?

    def initialize(@config : Config, @is_server : Bool, scid : Bytes? = nil)
      method = LibSSL.tls_method
      @ssl_ctx = LibSSL.ssl_ctx_new(method)
      LibSSL.ssl_ctx_ctrl(@ssl_ctx, LibSSL::SSL_CTRL_SET_MIN_PROTO_VERSION, LibSSL::TLS1_3_VERSION, nil)
      LibSSL.ssl_ctx_ctrl(@ssl_ctx, LibSSL::SSL_CTRL_SET_MAX_PROTO_VERSION, LibSSL::TLS1_3_VERSION, nil)
      LibSSL.SSL_CTX_set_ciphersuites(@ssl_ctx, "TLS_AES_128_GCM_SHA256")
      LibSSL.SSL_CTX_set_keylog_callback(@ssl_ctx, ->QUIC.keylog_cb)

      self_box = Box.box(self)
      LibSSL.ssl_ctx_ctrl(@ssl_ctx, 16, 0, self_box)

      
      tp = TransportParameters.new
      tp.max_idle_timeout = @config.max_idle_timeout
      tp.initial_max_data = @config.initial_max_data
      tp.initial_max_stream_data_bidi_local = @config.initial_max_stream_data_bidi_local
      tp.initial_max_stream_data_bidi_remote = @config.initial_max_stream_data_bidi_remote
      tp.initial_max_stream_data_uni = @config.initial_max_stream_data_uni
      tp.initial_max_streams_bidi = @config.initial_max_streams_bidi
      tp.initial_max_streams_uni = @config.initial_max_streams_uni
      tp.initial_source_connection_id = scid if scid
      
      io = IO::Memory.new
      tp.encode(io)
      @local_encoded_tp = io.to_slice

      if @is_server
        unless File.exists?(@config.cert_file) && File.exists?(@config.key_file)
          raise "TLS certificates not found! Please ensure '#{@config.cert_file}' and '#{@config.key_file}' exist."
        end
        res1 = LibSSL.ssl_ctx_use_certificate_chain_file(@ssl_ctx, @config.cert_file)
        res2 = LibSSL.ssl_ctx_use_privatekey_file(@ssl_ctx, @config.key_file, LibSSL::SSLFileType::PEM)
        Log.trace { "TLS SERVER INITIALIZATION: cert_load=#{res1}, key_load=#{res2}" }
        LibSSL.ssl_ctx_set_alpn_select_cb(@ssl_ctx, ->QUIC.alpn_select_cb, nil)
      end

      @ssl = LibSSL.ssl_new(@ssl_ctx)
      LibSSL.SSL_set_ex_data(@ssl, 0, self_box)

      @dispatch = Pointer(LibSSL::OSSL_DISPATCH).malloc(7)
      @dispatch[0] = LibSSL::OSSL_DISPATCH.new(function_id: LibSSL::OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, function: (->QUIC.crypto_send_cb(LibSSL::SSL, UInt8*, LibC::SizeT, LibC::SizeT*, Void*)).pointer)
      @dispatch[1] = LibSSL::OSSL_DISPATCH.new(function_id: LibSSL::OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, function: (->QUIC.crypto_recv_rcd_cb(LibSSL::SSL, UInt8**, LibC::SizeT*, Void*)).pointer)
      @dispatch[2] = LibSSL::OSSL_DISPATCH.new(function_id: LibSSL::OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, function: (->QUIC.crypto_release_rcd_cb(LibSSL::SSL, LibC::SizeT, Void*)).pointer)
      @dispatch[3] = LibSSL::OSSL_DISPATCH.new(function_id: LibSSL::OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, function: (->QUIC.yield_secret_cb(LibSSL::SSL, UInt32, Int32, UInt8*, LibC::SizeT, Void*)).pointer)
      @dispatch[4] = LibSSL::OSSL_DISPATCH.new(function_id: LibSSL::OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, function: (->QUIC.got_transport_params_cb(LibSSL::SSL, UInt8*, LibC::SizeT, Void*)).pointer)
      @dispatch[5] = LibSSL::OSSL_DISPATCH.new(function_id: LibSSL::OSSL_FUNC_SSL_QUIC_TLS_ALERT, function: (->QUIC.alert_cb(LibSSL::SSL, UInt8, Void*)).pointer)
      @dispatch[6] = LibSSL::OSSL_DISPATCH.new(function_id: 0, function: Pointer(Void).null)

      res_cbs = LibSSL.SSL_set_quic_tls_cbs(@ssl, @dispatch, self_box)
      Log.trace { "TLS INITIALIZATION: SSL_set_quic_tls_cbs returned #{res_cbs}" }

      if tp_bytes = @local_encoded_tp
        res = LibSSL.SSL_set_quic_tls_transport_params(@ssl, tp_bytes, tp_bytes.size.to_u64)
        Log.trace { "TLS INITIALIZATION: SSL_set_quic_tls_transport_params returned #{res}" }
      end

      if @is_server
        LibSSL.SSL_set_accept_state(@ssl)
      else
        LibSSL.ssl_set_verify(@ssl, 0, nil) # 0 = SSL_VERIFY_NONE
        LibSSL.SSL_set_connect_state(@ssl)
        alpn = Bytes[0x02, 0x68, 0x33] # "\x02h3"
        LibSSL.SSL_set_alpn_protos(@ssl, alpn, alpn.size)
        do_handshake
      end
    end

    def update_local_tp(tp : TransportParameters)
      io = IO::Memory.new
      tp.encode(io)
      @local_encoded_tp = io.to_slice
      if tp_bytes = @local_encoded_tp
        res = LibSSL.SSL_set_quic_tls_transport_params(@ssl, tp_bytes, tp_bytes.size)
        Log.trace { "TLS UPDATE: SSL_set_quic_tls_transport_params returned #{res}" }
      end
    end

    property recv_buf_level : UInt32 = LibSSL::OSSL_RECORD_PROTECTION_LEVEL_NONE

    def handle_data(data : Bytes, level : UInt32)
      @recv_buf_level = level
      if @recv_buf
        # Append data to existing buffer
        new_buf = Bytes.new(@recv_buf.not_nil!.size + data.size)
        @recv_buf.not_nil!.copy_to(new_buf[0, @recv_buf.not_nil!.size])
        data.copy_to(new_buf[@recv_buf.not_nil!.size, data.size])
        @recv_buf = new_buf
      else
        @recv_buf = data.dup
      end
      
      Log.trace { "TLS: handle_data called with #{data.size} bytes at level #{level}" }
      
      # Try to drive the handshake
      do_handshake
      
      # If handshake is complete, we might need SSL_read to process post-handshake data
      if handshake_complete?
        dummy = uninitialized UInt8[1]
        LibSSL.ssl_read(@ssl, dummy.to_unsafe, 0)
      end
    end

    def set_remote_tp(tp : TransportParameters)
      @remote_transport_parameters = tp
    end

    def process_keylog_line(line : String)
      parts = line.split(" ")
      return if parts.size < 3
      label = parts[0]
      secret = parts[2].hexbytes
      @on_secret.try &.call(label, secret)
    end

    def poll_initial : Bytes?
      bytes = @send_buf_initial.to_slice
      return nil if bytes.empty?
      result = Bytes.new(bytes.size)
      bytes.copy_to(result)
      @send_buf_initial.clear
      result
    end

    def poll_handshake : Bytes?
      bytes = @send_buf_handshake.to_slice
      return nil if bytes.empty?
      result = Bytes.new(bytes.size)
      bytes.copy_to(result)
      @send_buf_handshake.clear
      result
    end

    def poll_app : Bytes?
      bytes = @send_buf_app.to_slice
      return nil if bytes.empty?
      result = Bytes.new(bytes.size)
      bytes.copy_to(result)
      @send_buf_app.clear
      result
    end

    def do_handshake
      ret = LibSSL.SSL_do_handshake(@ssl)
      if ret <= 0
        err = LibSSL.ssl_get_error(@ssl, ret)
        Log.trace { "TLS: SSL_do_handshake returned #{ret}, error: #{err}" }
        while (err_code = LibCrypto.ERR_get_error) != 0
          buf = Bytes.new(256)
          LibCrypto.ERR_error_string_n(err_code, buf, buf.size.to_u64)
          Log.trace { "TLS: OpenSSL error: #{String.new(buf).strip(0.chr)}" }
        end
      else
        Log.trace { "TLS: SSL_do_handshake succeeded: #{ret}" }
      end
      ret
    end

    def handshake_complete? : Bool
      LibSSL.SSL_is_init_finished(@ssl) != 0
    end
    
    def finalize
      LibSSL.SSL_free(@ssl)
      LibSSL.SSL_CTX_free(@ssl_ctx)
    end
  end
end

lib LibSSL
  TLS1_3_VERSION = 0x0304
  SSL_CTRL_SET_MIN_PROTO_VERSION = 123
  SSL_CTRL_SET_MAX_PROTO_VERSION = 124
  
  fun SSL_is_init_finished(ssl : SSL) : Int32
  fun SSL_set_accept_state(ssl : SSL)
  fun SSL_set_connect_state(ssl : SSL)
  fun ssl_set_verify = SSL_set_verify(ssl : SSL, mode : Int32, callback : Void*) : Void
  fun SSL_do_handshake(ssl : SSL) : Int32
  
  fun SSL_set_alpn_protos(ssl : SSL, protos : UInt8*, protos_len : LibC::UInt) : Int32

  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND = 2001
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD = 2002
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD = 2003
  OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET = 2004
  OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS = 2005
  OSSL_FUNC_SSL_QUIC_TLS_ALERT = 2006

  OSSL_RECORD_PROTECTION_LEVEL_NONE = 0_u32
  OSSL_RECORD_PROTECTION_LEVEL_EARLY = 1_u32
  OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE = 2_u32
  OSSL_RECORD_PROTECTION_LEVEL_APPLICATION = 3_u32

  struct OSSL_DISPATCH
    function_id : Int32
    function : Void*
  end

  fun SSL_set_quic_tls_cbs(ssl : SSL, qtdis : OSSL_DISPATCH*, arg : Void*) : Int32

  SSL_EXT_CLIENT_HELLO = 0x0001
  SSL_EXT_TLS1_3_SERVER_HELLO = 0x0100
  SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS = 0x0200

  alias SSL_CTX_keylog_cb_func = (SSL, LibC::Char*) -> Void
  fun SSL_CTX_set_keylog_callback(ctx : SSLContext, cb : SSL_CTX_keylog_cb_func) : Void
  
  alias SSL_CTX_msg_cb_func = (Int32, Int32, Int32, Void*, LibC::SizeT, SSL, Void*) -> Void
  fun SSL_CTX_set_msg_callback(ctx : SSLContext, cb : SSL_CTX_msg_cb_func) : Void
  fun SSL_set_quic_tls_transport_params(ssl : SSL, params : UInt8*, params_len : LibC::SizeT) : Int32

  fun SSL_set_ex_data(ssl : SSL, idx : Int32, arg : Void*) : Int32
  fun SSL_get_ex_data(ssl : SSL, idx : Int32) : Void*
  fun SSL_free(ssl : SSL) : Void
  fun SSL_CTX_free(ctx : SSLContext) : Void
  fun SSL_CTX_set_ciphersuites(ctx : SSLContext, str : LibC::Char*) : Int32
end

lib LibCrypto
  fun BIO_s_mem : BioMethod*
  fun BIO_new(method : BioMethod*) : Bio*
  fun BIO_write(bio : Bio*, data : UInt8*, len : Int32) : Int32
  fun BIO_read(bio : Bio*, data : UInt8*, len : Int32) : Int32
  fun BIO_ctrl_pending(bio : Bio*) : Int32
  fun ERR_get_error : UInt64
  fun ERR_error_string_n(e : UInt64, buf : UInt8*, len : LibC::SizeT) : Void
  fun CRYPTO_malloc(num : LibC::SizeT, file : LibC::Char*, line : LibC::Int) : Void*
  fun CRYPTO_free(ptr : Void*, file : LibC::Char*, line : LibC::Int) : Void
end
