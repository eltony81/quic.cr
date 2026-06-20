require "../src/quic"

Log.setup_from_env(default_level: :info)

# ============================================================
# Example: High-Level H3::Server with Router + Middleware
# ============================================================
#
# Run:
#   crystal run examples/h3_server_routed.cr
#
# Test:
#   curl -v --http3 https://127.0.0.1:4433/             --insecure
#   curl -v --http3 https://127.0.0.1:4433/users/42     --insecure
#   curl -v --http3 https://127.0.0.1:4433/echo         --insecure \
#        -X POST -H "Content-Type: application/json"   \
#        -d '{"msg":"hello quic.cr"}'
#   curl -v --http3 https://127.0.0.1:4433/greet?name=World --insecure
# ============================================================

router = H3::Router.new

# ── Middleware: request logging ──────────────────────────────
router.use do |ctx, next_handler|
  start = Time.instant
  next_handler.call(ctx)
  elapsed = (Time.instant - start).total_milliseconds
  Log.info { "#{ctx.request.method} #{ctx.request.path} → #{ctx.response.status} (#{elapsed.round(2)} ms)" }
end

# ── Middleware: CORS headers ─────────────────────────────────
router.use do |ctx, next_handler|
  ctx.set_header "access-control-allow-origin", "*"
  ctx.set_header "x-powered-by", "quic.cr"
  next_handler.call(ctx)
end

# ── Routes ───────────────────────────────────────────────────

router.get "/" do |ctx|
  ctx.html <<-HTML
    <!DOCTYPE html>
    <html>
      <head><title>quic.cr HTTP/3 Server</title></head>
      <body>
        <h1>🚀 Welcome to quic.cr HTTP/3!</h1>
        <p>Try: <code>GET /users/:id</code>, <code>POST /echo</code>, <code>GET /greet?name=World</code></p>
      </body>
    </html>
  HTML
end

router.get "/greet" do |ctx|
  name = ctx.params["name"]? || "stranger"
  ctx.json %({"message": "Hello, #{name}!", "server": "quic.cr"})
end

router.get "/users/:id" do |ctx|
  id = ctx.request.path_params["id"]
  ctx.json %({"user": {"id": "#{id}", "status": "active"}})
end

router.post "/echo" do |ctx|
  if ctx.request.json?
    ctx.json %({"echo": #{ctx.body_string.inspect}, "bytes": #{ctx.request.body.size}})
  else
    ctx.text "Echo: #{ctx.body_string}"
  end
end

router.delete "/users/:id" do |ctx|
  id = ctx.request.path_params["id"]
  ctx.json %({"deleted": true, "id": "#{id}"})
end

# ── Start the server ─────────────────────────────────────────
H3::Server.new(router).listen(
  host: "127.0.0.1",
  port: 4433,
  cert: File.join(__DIR__, "..", "cert.pem"),
  key:  File.join(__DIR__, "..", "key.pem")
)
