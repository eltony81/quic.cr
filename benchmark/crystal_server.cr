require "../src/quic"

# Minimal Crystal HTTP/3 benchmark server.
# Routes mirror the Go server so the benchmark hits identical logic.
Log.setup_from_env(default_level: :warn)

router = H3::Router.new

router.get "/" do |ctx|
  ctx.html <<-HTML
    <!DOCTYPE html><html><body><h1>Crystal HTTP/3 Server</h1><p>quic.cr benchmark</p></body></html>
  HTML
end

router.get "/greet" do |ctx|
  name = ctx.params["name"]? || "stranger"
  ctx.json %({"message":"Hello, #{name}!","server":"quic.cr"})
end

router.get "/users/:id" do |ctx|
  id = ctx.request.path_params["id"]
  ctx.json %({"user":{"id":"#{id}","status":"active"}})
end

router.delete "/users/:id" do |ctx|
  id = ctx.request.path_params["id"]
  ctx.json %({"deleted":true,"id":"#{id}"})
end

router.post "/echo" do |ctx|
  if ctx.request.json?
    ctx.json %({"echo":#{ctx.body_string.inspect},"bytes":#{ctx.request.body.size}})
  else
    ctx.text "Echo: #{ctx.body_string}"
  end
end

router.get "/healthz" do |ctx|
  ctx.json %({"status":"ok","server":"quic.cr"})
end

H3::Server.new(router).listen(
  host: "127.0.0.1",
  port: 4433,
  cert: File.join(__DIR__, "..", "cert.pem"),
  key:  File.join(__DIR__, "..", "key.pem")
)
