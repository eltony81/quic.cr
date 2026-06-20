require "socket"
require "uri"

module H3
  # High-level HTTP/3 server with two operation modes:
  #
  # **Mode 1 — Low-level handler block** (backwards-compatible):
  #
  #   server = H3::Server.new do |headers, body|
  #     { {":status" => "200"}, "hello".to_slice }
  #   end
  #
  # **Mode 2 — Router-based** (full middleware + routing DSL):
  #
  #   router = H3::Router.new
  #   router.use { |ctx, nxt| Log.info { ctx.request.path }; nxt.call(ctx) }
  #   router.get "/" { |ctx| ctx.text "Hello!" }
  #   router.get "/users/:id" { |ctx| ctx.json %({"id":"#{ctx.request.path_params["id"]}"}) }
  #
  #   H3::Server.new(router).listen("0.0.0.0", 4433, cert: "cert.pem", key: "key.pem")
  #
  # When using `listen`, the server manages its own QUIC::Server + UDP loop.
  class Server
    Log = ::Log.for("H3::Server")

    # Low-level handler type (backwards-compatible).
    alias LowLevelHandler = Proc(Hash(String, String), Bytes, {Hash(String, String), Bytes})

    @low_level_handler : LowLevelHandler?
    @router : H3::Router?

    # ------------------------------------------------------------------ Constructors

    # Mode 1: low-level block handler.
    def initialize(&handler : Hash(String, String), Bytes -> {Hash(String, String), Bytes})
      @low_level_handler = handler
    end

    # Mode 2: router-based.
    def initialize(router : H3::Router)
      @router = router
    end

    # ------------------------------------------------------------------ Blocking listen

    # Starts a fully managed QUIC/UDP server loop.
    #
    # Parameters:
    # - host       — bind address (default "0.0.0.0")
    # - port       — UDP port (default 4433)
    # - cert       — path to TLS certificate PEM
    # - key        — path to TLS private key PEM
    # - max_data   — connection-level flow control window (default 10 MB)
    def listen(
      host     : String      = "0.0.0.0",
      port     : Int32       = 4433,
      cert     : String      = "cert.pem",
      key      : String      = "key.pem",
      max_data : UInt64      = 10_000_000_u64
    )
      config = QUIC::Config.new
      config.cert_file                         = cert
      config.key_file                          = key
      config.initial_max_data                  = max_data
      config.initial_max_stream_data_bidi_local  = 1_000_000_u64
      config.initial_max_stream_data_bidi_remote = 1_000_000_u64
      config.initial_max_streams_bidi          = 128_u64
      config.initial_max_streams_uni           = 128_u64
      config.initial_max_stream_data_uni       = 1_000_000_u64

      udp = UDPSocket.new
      udp.bind(host, port)
      Log.info { "🚀 HTTP/3 Server listening on udp://#{host}:#{port}" }

      connections    = {} of String => {QUIC::Connection, H3::Connection}
      handled_streams = Set(Tuple(String, UInt64)).new
      buf    = Bytes.new(65536)
      out_buf = Bytes.new(65536)

      loop do
        size, client_addr = udp.receive(buf)
        data = buf[0, size]

        conn_key  = extract_dcid(data)
        conn_tuple = connections[conn_key]?

        if conn_tuple.nil?
          Log.debug { "New connection (DCID: #{conn_key})" }
          quic_conn = QUIC::Connection.new(config, is_server: true)
          h3_conn   = H3::Connection.new(quic_conn)
          conn_tuple = {quic_conn, h3_conn}
          connections[conn_key] = conn_tuple

          ctrl = h3_conn.open_uni_stream(0_u64)
          sf   = H3::SettingsFrame.new
          sf.settings = {0x01_u64 => 0_u64, 0x07_u64 => 100_u64, 0x06_u64 => 100_u64}
          h3_conn.write_frame(ctrl, sf)
        end

        quic_conn, h3_conn = conn_tuple
        quic_conn.recv(data)

        if scid = quic_conn.scid
          connections[scid.hexstring] = conn_tuple
        end

        # Dispatch new client-initiated bidirectional streams (ID % 4 == 0)
        quic_conn.streams.each do |stream_id, _stream|
          next unless stream_id % 4 == 0
          stream_key = {conn_key, stream_id}
          next if handled_streams.includes?(stream_key)
          handled_streams << stream_key

          sock = QUIC::StreamSocket.new(quic_conn, stream_id)
          begin
            handle_request(h3_conn, sock)
            Log.debug { "Handled stream #{stream_id}" }
          rescue e
            Log.error { "Stream #{stream_id} error: #{e.class} — #{e.message}" }
          end
        end

        while (n = quic_conn.send(out_buf)) > 0
          udp.send(out_buf[0, n], client_addr)
        end
      end
    rescue e : Exception
      Log.error { "Server fatal error: #{e.message}" }
    end

    # ------------------------------------------------------------------ Request dispatch

    # Handles a single request on the given stream IO.
    # Called internally by `listen` and directly in unit tests.
    def handle_request(h3_conn : H3::Connection, stream : IO, remote_address : String = "")
      req_frame = h3_conn.read_frame(stream)
      return unless req_frame.is_a?(HeadersFrame)

      body = Bytes.empty
      begin
        nxt = h3_conn.read_frame(stream)
        body = nxt.data if nxt.is_a?(DataFrame)
      rescue
      end

      if router = @router
        # ---- Mode 2: Router-based dispatch ----------------------------------
        request  = H3::Request.new(req_frame.headers, body, remote_address)
        response = H3::Response.new
        ctx      = H3::Context.new(request, response)

        unless router.dispatch(ctx)
          ctx.not_found
        end

        h3_conn.write_frame(stream, HeadersFrame.new(response.to_h3_headers))
        body_bytes = response.body_bytes
        h3_conn.write_frame(stream, DataFrame.new(body_bytes)) unless body_bytes.empty?

      elsif handler = @low_level_handler
        # ---- Mode 1: Low-level block handler (backwards-compatible) ---------
        resp_headers, resp_body = handler.call(req_frame.headers, body)
        h3_conn.write_frame(stream, HeadersFrame.new(resp_headers))
        h3_conn.write_frame(stream, DataFrame.new(resp_body)) unless resp_body.empty?
      end

      if stream.responds_to?(:close_local)
        stream.close_local
      end
    end

    # ------------------------------------------------------------------ Private

    private def extract_dcid(data : Bytes) : String
      io       = IO::Memory.new(data)
      first    = io.read_byte || 0_u8
      is_long  = (first & 0x80) != 0
      if is_long
        io.skip(4)   # version
        len  = io.read_byte || 0_u8
        dcid = Bytes.new(len)
        io.read_fully(dcid)
        dcid.hexstring
      else
        dcid = Bytes.new(8)
        io.read_fully(dcid)
        dcid.hexstring
      end
    rescue
      "unknown"
    end
  end
end
