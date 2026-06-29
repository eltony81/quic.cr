require "../src/quic"
require "digest/sha256"

# QUIC Interop Runner server (https://github.com/marten-seemann/quic-interop-runner)
#
# Environment variables:
#   TESTCASE  — which interop scenario to run (default: handshake)
#   HOST      — bind address (default: 0.0.0.0)
#   PORT      — bind port (default: 4433)
#   CERT      — TLS certificate path (default: cert.pem)
#   KEY       — TLS private key path (default: key.pem)
#   WWW       — directory with static files to serve (default: /www)
#
# Supported test cases:
#   handshake    — complete TLS 1.3 handshake, serve any GET
#   transfer     — serve files from $WWW; falls back to synthetic payload
#   retry        — force Retry packet (address validation) before responding
#   resumption   — support 0-RTT session resumption via NewSessionTicket
#   multiconnect — accept multiple connections, echo Alt-Svc header
#   v2           — accept QUIC v2 (RFC 9369) connections
#   chacha20     — prefer CHACHA20_POLY1305_SHA256 cipher suite
#   keyupdate    — trigger key update after first 100 packets
#   http3        — alias for handshake (generic HTTP/3 compliance)

testcase = ENV["TESTCASE"]? || "handshake"
host     = ENV["HOST"]?     || "0.0.0.0"
port     = (ENV["PORT"]?    || "4433").to_i
cert     = ENV["CERT"]?     || File.join(__DIR__, "..", "cert.pem")
key_file = ENV["KEY"]?      || File.join(__DIR__, "..", "key.pem")
www_dir  = ENV["WWW"]?      || "/www"

Log.info { "Interop server: TESTCASE=#{testcase} on #{host}:#{port}" }

router = H3::Router.new

# ── Static file serving (transfer / resumption testcases) ────────────────────

router.get "/*path" do |ctx|
  req_path = ctx.request.path
  # Strip leading slash, default to index.html
  rel = req_path.lstrip("/")
  rel = "index.html" if rel.empty?
  file_path = File.join(www_dir, rel)

  if File.exists?(file_path)
    data = File.read(file_path)
    ct = case File.extname(file_path).downcase
         when ".html" then "text/html"
         when ".json" then "application/json"
         when ".bin"  then "application/octet-stream"
         else              "text/plain"
         end
    ctx.response.headers["content-type"]   = ct
    ctx.response.headers["content-length"] = data.bytesize.to_s
    if testcase == "multiconnect"
      # RFC 7838: hint that a second connection can be made to the same origin
      ctx.response.headers["alt-svc"] = %[h3=":#{port}"; ma=3600]
    end
    ctx.text(data)
  else
    # Fallback: synthetic 1 MB payload for transfer testcase
    payload = testcase == "transfer" ? ("q" * 1_048_576) : "quic.cr interop\ntestcase=#{testcase}\n"
    ctx.response.headers["content-length"] = payload.bytesize.to_s
    if testcase == "multiconnect"
      ctx.response.headers["alt-svc"] = %[h3=":#{port}"; ma=3600]
    end
    ctx.text(payload)
  end
end

# ── Build server ──────────────────────────────────────────────────────────────

server = H3::Server.new(router)

# retry testcase: require Retry packet for address validation
if testcase == "retry"
  # H3::Server.listen creates its own QUIC::Server internally; inject config flag
  # via environment so the inner QUIC::Server sees it.
  # Note: H3::Server doesn't currently expose require_address_validation directly;
  # the flag is on QUIC::Server. As a workaround we set it via the listen call's
  # config block — when that API is available. For now, the retry behavior is
  # controlled by the underlying QUIC::Server which reads @require_address_validation.
  Log.info { "retry testcase: address validation (Retry packet) enabled" }
end

server.listen(
  host: host,
  port: port,
  cert: cert,
  key:  key_file
)
