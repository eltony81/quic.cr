require "../src/quic"
require "../src/h3/server"

Log.setup_from_env(default_level: :info)

server_log = Log.for("H3::ExampleServer")

# Create a low-level handler-block H3 server
server = H3::Server.new do |headers, body|
  method = headers[":method"]? || "UNKNOWN"
  path = headers[":path"]? || "/"
  server_log.info { "⬇️  Received Request: #{method} #{path}" }
  
  if body.size > 0
    server_log.info { "   Request Body: #{String.new(body)}" }
  end

  response_headers = {
    ":status"      => "200",
    "content-type" => "text/plain",
    "server"       => "quic.cr/h3-example-server"
  }
  response_body = "Hello from the HTTP/3 Server block handler!\n".to_slice

  server_log.info { "⬆️  Responding with status 200 (length: #{response_body.size})" }
  {response_headers, response_body}
end

# Start the UDP loop using standard certificates
cert_path = File.join(__DIR__, "..", "cert.pem")
key_path = File.join(__DIR__, "..", "key.pem")

server_log.info { "🚀 Starting HTTP/3 Server Example..." }
server.listen("127.0.0.1", 4433, cert: cert_path, key: key_path)
