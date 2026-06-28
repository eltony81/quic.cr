require "../src/quic"
require "digest/sha256"

router = H3::Router.new

router.get "/" do |ctx|
  ctx.text "Hello from quic.cr!"
end

router.get "/healthz" do |ctx|
  ctx.json %({"status":"ok"})
end

router.get "/ping" do |ctx|
  ctx.text "pong"
end

router.get "/method" do |ctx|
  ctx.text ctx.request.method
end

router.post "/echo" do |ctx|
  ctx.text ctx.body_string
end

router.put "/echo" do |ctx|
  ctx.text ctx.body_string
end

router.patch "/echo" do |ctx|
  ctx.text ctx.body_string
end

router.delete "/resource" do |ctx|
  ctx.response.status = 204
end

router.head "/" do |ctx|
  ctx.response.set_header("x-server", "quic.cr")
  ctx.response.set_header("content-type", "text/plain; charset=utf-8")
  ctx.response.set_header("content-length", "20")
  ctx.response.status = 200
end

router.get "/status/:code" do |ctx|
  code = ctx.request.path_params["code"].to_i rescue 200
  ctx.text("Status #{code}", code)
end

router.get "/large" do |ctx|
  n = (ctx.request.query_params["n"]?.try(&.to_i?) || 65536).clamp(0, 10_485_760)
  ctx.text("x" * n)
end

router.get "/echo-headers" do |ctx|
  pairs = ctx.request.headers
    .reject { |k, _| k.starts_with?("_param_") || k.starts_with?(":") }
    .map { |k, v| %("#{k}":"#{v.gsub("\"", "\\\"").gsub("\\", "\\\\")}") }
  ctx.json "{" + pairs.join(",") + "}"
end

router.post "/upload" do |ctx|
  size = ctx.body_string.bytesize
  ctx.json %({"received":#{size}})
end

router.get "/slow" do |ctx|
  ms = (ctx.request.query_params["ms"]?.try(&.to_i?) || 0).clamp(0, 5000)
  sleep ms.milliseconds
  ctx.text "ok"
end

router.post "/digest" do |ctx|
  body = ctx.body_string
  hex = Digest::SHA256.hexdigest(body)
  ctx.json %({"sha256":"#{hex}","size":#{body.bytesize}})
end

PAYLOAD_100K = "x" * 102_400

router.get "/100k" do |ctx|
  ctx.response.headers["content-type"] = "application/octet-stream"
  ctx.text(PAYLOAD_100K)
end

router.get "/repeat" do |ctx|
  n = (ctx.request.query_params["n"]?.try(&.to_i?) || 0).clamp(0, 10_000_000)
  c = ctx.request.query_params["c"]?.try { |s| s[0]? } || 'x'
  ctx.text(c.to_s * n)
end

# Trigger GOAWAY drain on the current connection (used by e2e suite 26).
# Sends a GOAWAY frame on the H3 control stream, signalling graceful shutdown.
router.get "/send-goaway" do |ctx|
  if h3 = ctx.h3_conn
    sid = ctx.request_stream_id || 0_u64
    h3.send_goaway(sid)
  end
  ctx.text "ok"
end

# Server Push demo: attempts to push /push-asset before the main response.
# The push is only sent when the client has authorised it via MAX_PUSH_ID
# (RFC 9114 §4.6). Without that, push_resource is a silent no-op and the
# main response is delivered normally.
router.get "/push-demo" do |ctx|
  ctx.push_resource(
    "/push-asset",
    "pushed content",
    {"content-type" => "text/plain"}
  )
  ctx.text "main response"
end

H3::Server.new(router).listen(
  host: "127.0.0.1",
  port: 4433,
  cert: File.join(__DIR__, "..", "cert.pem"),
  key:  File.join(__DIR__, "..", "key.pem")
)
