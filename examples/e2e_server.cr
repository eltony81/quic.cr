require "../src/quic"

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

H3::Server.new(router).listen(
  host: "127.0.0.1",
  port: 4433,
  cert: File.join(__DIR__, "..", "cert.pem"),
  key:  File.join(__DIR__, "..", "key.pem")
)
