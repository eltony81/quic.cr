require "../src/quic"
require "../src/h3/server"
require "../src/h3/client"

Log.setup_from_env(default_level: :info)
demo_log = Log.for("SelfSignedDemo")

# This example demonstrates how to run an HTTP/3 Server and Client in two modes:
# 1. Automatic Self-Signed mode (no certificates needed on disk; generated on the fly via openssl)
# 2. Disk Certificate mode (loading cert.pem and key.pem from disk)

host = "127.0.0.1"
port = 4545

# Create a basic router with a simple ping endpoint
router = H3::Router.new
router.get "/ping" do |ctx|
  ctx.text "pong (from auto-generated self-signed H3 server!)"
end

# Spawn the H3 server in a background fiber so we can run the client in the main fiber.
spawn do
  server = H3::Server.new(router)
  
  # METHOD 1: Automatic Self-Signed Certificate Generation
  # We specify filenames that do not exist yet. quic.cr will automatically detect 
  # their absence and call OpenSSL to generate a self-signed key/cert pair on the fly!
  auto_cert = "auto_cert.pem"
  auto_key  = "auto_key.pem"
  
  # Clean up any leftover files from previous runs to demonstrate generation
  File.delete(auto_cert) if File.exists?(auto_cert)
  File.delete(auto_key) if File.exists?(auto_key)
  
  demo_log.info { "Starting server on port #{port}. Certificates will be generated automatically..." }
  
  # This call starts the server UDP listening loop.
  server.listen(host, port, cert: auto_cert, key: auto_key)
end

# Wait a brief moment for the server fiber to bind and generate the certificate
sleep 0.5.seconds

# --- HTTP/3 CLIENT RUN ---
demo_log.info { "Starting HTTP/3 client..." }

config = QUIC::Config.new
config.initial_max_data = 10_000_000_u64
config.initial_max_stream_data_bidi_local = 1_000_000_u64
config.initial_max_stream_data_bidi_remote = 1_000_000_u64
config.initial_max_streams_bidi = 100_u64
config.initial_max_streams_uni = 100_u64
config.initial_max_stream_data_uni = 1_000_000_u64

# Connect to the server. The client automatically bypasses verification warnings
# since it is connecting to a self-signed server locally.
client = H3::Client.new(host, port, config)

begin
  demo_log.info { "Sending GET /ping to HTTP/3 Server..." }
  headers, body, _ = client.get("/ping")
  
  puts "\n[Response Status/Headers]"
  headers.each { |k, v| puts "  #{k}: #{v}" }
  
  puts "\n[Response Body]"
  puts String.new(body)
  puts
ensure
  client.close
  demo_log.info { "Client connection closed." }
  
  # Clean up generated cert files to keep the directory pristine
  File.delete("auto_cert.pem") if File.exists?("auto_cert.pem")
  File.delete("auto_key.pem") if File.exists?("auto_key.pem")
end
