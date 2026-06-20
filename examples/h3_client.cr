require "../src/quic"
require "../src/h3/client"

Log.setup_from_env(default_level: :info)

puts "🚀 Starting Crystal HTTP/3 High-Level Client Example..."

# Setup QUIC Configuration matching server limits
config = QUIC::Config.new
config.initial_max_data = 10_000_000_u64
config.initial_max_stream_data_bidi_local = 1_000_000_u64
config.initial_max_stream_data_bidi_remote = 1_000_000_u64
config.initial_max_streams_bidi = 100_u64
config.initial_max_streams_uni = 100_u64
config.initial_max_stream_data_uni = 1_000_000_u64

# Connect to the local routed server
h3_client = H3::Client.new("127.0.0.1", 4433, config)
puts "🔌 Connected to HTTP/3 Server at 127.0.0.1:4433"

begin
  puts "\n--- Performing GET /greet?name=Crystal ---"
  headers, body, trailers = h3_client.get("/greet?name=Crystal")
  
  puts "[Response Status/Headers]"
  headers.each { |k, v| puts "  #{k}: #{v}" }
  
  puts "\n[Response Body]"
  puts String.new(body)

  if trailers.size > 0
    puts "\n[Response Trailers]"
    trailers.each { |k, v| puts "  #{k}: #{v}" }
  end

  puts "\n--- Performing POST /greet with JSON payload ---"
  post_headers = {"content-type" => "application/json"}
  post_body = %({"name": "Crystal-H3-Client", "status": "active"})
  headers, body, trailers = h3_client.post("/greet", post_body, post_headers)

  puts "[Response Status/Headers]"
  headers.each { |k, v| puts "  #{k}: #{v}" }
  
  puts "\n[Response Body]"
  puts String.new(body)

  if trailers.size > 0
    puts "\n[Response Trailers]"
    trailers.each { |k, v| puts "  #{k}: #{v}" }
  end
ensure
  h3_client.close
  puts "\n🔌 Client connection closed."
end
