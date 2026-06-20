require "../src/quic"

Log.setup_from_env(default_level: :info)
require "../src/h3/client"

# Setup QUIC Configuration
config = QUIC::Config.new
config.initial_max_data = 10_000_000_u64
config.initial_max_stream_data_bidi_local = 1_000_000_u64
config.initial_max_stream_data_bidi_remote = 1_000_000_u64
config.initial_max_streams_bidi = 100_u64
config.initial_max_streams_uni = 100_u64
config.initial_max_stream_data_uni = 1_000_000_u64

puts "🚀 Starting quic.cr HTTP/3 Client..."

# Connect to the server
client = H3::Client.new("127.0.0.1", 4433, config)
puts "✅ Connected to 127.0.0.1:4433"

begin
  puts "\n--- Executing GET / ---"
  headers, body, trailers = client.get("/")
  
  puts "[Response Headers]"
  headers.each { |k, v| puts "  #{k}: #{v}" }
  
  puts "\n[Response Body]"
  puts String.new(body)
  
  puts "\n--- Executing POST / ---"
  post_headers = {"content-type" => "application/json"}
  post_body = %({"name": "HTTP/3 Client Test"})
  headers, body, trailers = client.post("/", post_body, post_headers)
  
  puts "[Response Headers]"
  headers.each { |k, v| puts "  #{k}: #{v}" }
  
  puts "\n[Response Body]"
  puts String.new(body)
ensure
  client.close
  puts "\n🔌 Client closed."
end
