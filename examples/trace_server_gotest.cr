require "../src/quic"

Log.setup_from_env(default_level: :trace)

router = H3::Router.new
router.get "/" do |ctx|; ctx.text "Hello from quic.cr!"; end
router.get "/healthz" do |ctx|; ctx.json %({"status":"ok"}); end
router.post "/echo" do |ctx|; ctx.text ctx.body_string; end

H3::Server.new(router).listen(
  host: "127.0.0.1", port: 4433,
  cert: File.join(__DIR__, "..", "cert.pem"),
  key: File.join(__DIR__, "..", "key.pem")
)
