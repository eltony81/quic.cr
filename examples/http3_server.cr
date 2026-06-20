require "../src/quic"
require "socket"
require "uri"

Log.setup_from_env(default_level: :info)

# Reopen QUIC::Connection to expose the stream buffer map for request routing
class QUIC::Connection
  getter streams
end

# Create the H3 server and request handler
h3_server = H3::Server.new do |headers, body|
  method = headers[":method"]? || "UNKNOWN"
  path_with_query = headers[":path"]? || "/"
  
  uri = URI.parse(path_with_query)
  path = uri.path
  query_params = uri.query_params
  authority = headers[":authority"]? || "UNKNOWN"
  
  puts "\n[Server] ⬇️  Received Request:"
  puts "  Method: #{method}"
  puts "  Authority: #{authority}"
  puts "  Path:   #{path}"
  
  if query_params.size > 0
    puts "  Query Parameters:"
    query_params.each do |k, v|
      puts "    - #{k}: #{v}"
    end
  end
  
  puts "  Headers:"
  headers.each do |k, v|
    next if k.starts_with?(":") # Skip pseudo-headers
    puts "    - #{k}: #{v}"
  end
  
  if body.size > 0
    puts "  Body: #{String.new(body)}"
  end

  response_headers = {
    ":status"      => "200",
    "content-type" => "text/plain",
    "server"       => "quic.cr/http3-server"
  }
  
  body_str = String.new(body)
  response_string = case method
                    when "GET"
                      "Hello from the quic.cr HTTP/3 Server! You performed a GET request on #{path}.\n"
                    when "POST", "PUT", "PATCH"
                      transform_body = body_str.upcase
                      <<-JSON
                      {
                        "status": "success",
                        "action_performed": "#{method}",
                        "path_accessed": "#{path}",
                        "bytes_processed": #{body.size},
                        "transformed_data": "#{transform_body.gsub("\"", "\\\"").gsub("\n", "\\n")}"
                      }
                      JSON
                    when "DELETE"
                      "Resource at #{path} has been DELETED.\n"
                    else
                      "Received #{method} request on #{path}.\n"
                    end
  
  response_body = response_string.to_slice
  
  puts "[Server] ⬆️  Sending Response 200 OK"
  {response_headers, response_body}
end

# Set up QUIC connection configuration
config = QUIC::Config.new
config.initial_max_data = 10_000_000_u64
config.initial_max_stream_data_bidi_local = 1_000_000_u64
config.initial_max_stream_data_bidi_remote = 1_000_000_u64
config.cert_file = File.join(__DIR__, "..", "cert.pem")
config.key_file = File.join(__DIR__, "..", "key.pem")
config.initial_max_streams_bidi = 100_u64
config.initial_max_streams_uni = 100_u64
config.initial_max_stream_data_uni = 1_000_000_u64

server_socket = UDPSocket.new
server_socket.bind("127.0.0.1", 4433)
puts "================================================="
puts "🚀 HTTP/3 Server listening on udp://127.0.0.1:4433"
puts "================================================="

# Dictionary to keep track of active QUIC connections by Connection ID
connections = {} of String => {QUIC::Connection, H3::Connection}
handled_streams = Set(Tuple(String, UInt64)).new
buffer = Bytes.new(4096)
out_buf = Bytes.new(4096)

loop do
  # 1. Receive UDP packet
  size, client_addr = server_socket.receive(buffer)
  data = buffer[0, size]

  # 2. Extract Destination Connection ID (DCID) to route the packet
  io = IO::Memory.new(data)
  first_byte = io.read_byte || 0_u8
  is_long = (first_byte & 0x80) != 0

  dcid = Bytes.empty
  if is_long
    # Long header: read version and DCID length
    io.skip(4) # skip version
    dcid_len = io.read_byte || 0_u8
    dcid = Bytes.new(dcid_len)
    io.read_fully(dcid)
  else
    # Short header: DCID is typically 8 bytes in this implementation
    dcid = Bytes.new(8)
    io.read_fully(dcid)
  end

  conn_key = dcid.hexstring
  conn_tuple = connections[conn_key]?

  # 3. Handle new connections
  if conn_tuple.nil?
    puts "[Server] New connection detected (DCID: #{conn_key})"
    quic_conn = QUIC::Connection.new(config, is_server: true)
    h3_conn = H3::Connection.new(quic_conn)
    conn_tuple = {quic_conn, h3_conn}
    connections[conn_key] = conn_tuple
    
    # Establish server control stream and send H3 settings
    control_stream = h3_conn.open_uni_stream(0_u64)
    settings = H3::SettingsFrame.new
    settings.settings = { 
      0x01_u64 => 0_u64, # QPACK_MAX_TABLE_CAPACITY
      0x07_u64 => 100_u64,  # QPACK_BLOCKED_STREAMS
      0x06_u64 => 100_u64   # MAX_FIELD_SECTION_SIZE
    }
    h3_conn.write_frame(control_stream, settings)
  end

  quic_conn, h3_conn = conn_tuple
  
  # 4. Feed received packet to the QUIC state machine
  quic_conn.recv(data)
  
  # Map the server-chosen Source Connection ID (SCID) to the same connection
  if scid = quic_conn.scid
    connections[scid.hexstring] = conn_tuple
  end

  # 5. Check if there are new client bidirectional streams with HTTP/3 data
  quic_conn.streams.each do |stream_id, stream|
    # HTTP/3 requests are on client-initiated bidirectional streams (ID % 4 == 0)
    if stream_id % 4 == 0
      stream_key = {conn_key, stream_id}
      unless handled_streams.includes?(stream_key)
        stream_socket = QUIC::StreamSocket.new(quic_conn, stream_id)
        begin
          h3_server.handle_request(h3_conn, stream_socket)
          handled_streams << stream_key
          puts "[Server] Successfully responded to request on stream #{stream_id}"
        rescue e
          puts "[Server Error] Failed to handle request on stream #{stream_id}: #{e.class} - #{e.message}"
          e.backtrace.each { |line| puts "  #{line}" }
          handled_streams << stream_key
        end
      end
    end
  end

  # 6. Process and send any outgoing packets generated by the connection
  while (out_size = quic_conn.send(out_buf)) > 0
    server_socket.send(out_buf[0, out_size], client_addr)
  end
end
