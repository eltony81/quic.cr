require "../src/quic"
require "socket"

# Reopen QUIC::Connection to expose the stream buffer map for request routing
class QUIC::Connection
  getter streams
end

# Create the H3 server and request handler
h3_server = H3::Server.new do |headers, body|
  puts "Server received headers: #{headers}"
  response_headers = {
    ":status"      => "200",
    "content-type" => "text/plain",
    "server"       => "quic.cr/validate-server"
  }
  response_body = "Hello from the quic.cr HTTP/3 validation server!\n".to_slice
  {response_headers, response_body}
end

config = QUIC::Config.new
config.initial_max_data = 10_000_000_u64
config.initial_max_stream_data_bidi_local = 1_000_000_u64
config.initial_max_stream_data_bidi_remote = 1_000_000_u64
config.initial_max_streams_bidi = 100_u64
config.initial_max_streams_uni = 100_u64
config.initial_max_stream_data_uni = 1_000_000_u64

server_socket = UDPSocket.new
server_socket.bind("127.0.0.1", 4433)
puts "HTTP/3 Validation Server listening on udp://127.0.0.1:4433"

connections = {} of String => {QUIC::Connection, H3::Connection}
handled_streams = Set(Tuple(String, UInt64)).new

buffer = Bytes.new(2048)

loop do
  size, client_addr = server_socket.receive(buffer)
  data = buffer[0, size]
  puts "Server received #{size} bytes from #{client_addr}"

  io = IO::Memory.new(data)
  first_byte = io.read_byte.not_nil!
  is_long = (first_byte & 0x80) != 0
  puts "First byte: #{first_byte.to_s(16)}, is_long: #{is_long}"

  dcid = Bytes.empty
  if is_long
    # Parse version, DCID, SCID
    _version = IO::ByteFormat::NetworkEndian.decode(UInt32, io)
    dcid_len = io.read_byte.not_nil!
    dcid = Bytes.new(dcid_len)
    io.read_fully(dcid)
  else
    dcid = Bytes.new(8)
    io.read_fully(dcid)
  end

  conn_key = dcid.hexstring
  puts "Parsed DCID hex: #{conn_key}"
  conn_tuple = connections[conn_key]?

  if conn_tuple.nil?
    puts "Creating new connection context for DCID #{conn_key}"
    quic_conn = QUIC::Connection.new(config, is_server: true)
    h3_conn = H3::Connection.new(quic_conn)
    conn_tuple = {quic_conn, h3_conn}
    connections[conn_key] = conn_tuple
    
    # Establish server control stream
    control_stream = h3_conn.open_uni_stream(0_u64)
    settings = H3::SettingsFrame.new
    settings.settings = { 
      0x01_u64 => 1000_u64, # QPACK_MAX_TABLE_CAPACITY
      0x07_u64 => 100_u64,  # QPACK_BLOCKED_STREAMS
      0x06_u64 => 100_u64   # MAX_FIELD_SECTION_SIZE
    }
    h3_conn.write_frame(control_stream, settings)
  end

  quic_conn, h3_conn = conn_tuple
  quic_conn.recv(data)
  if scid = quic_conn.scid
    connections[scid.hexstring] = conn_tuple
  end

  # Check if there are new client bidirectional streams with data
  quic_conn.streams.each do |stream_id, stream|
    if stream_id % 4 == 0
      stream_key = {conn_key, stream_id}
      unless handled_streams.includes?(stream_key)
        stream_socket = QUIC::StreamSocket.new(quic_conn, stream_id)
        begin
          h3_server.handle_request(h3_conn, stream_socket)
          handled_streams << stream_key
          puts "Successfully handled H3 request on stream #{stream_id}"
        rescue e
          # Data or frames not complete yet
        end
      end
    end
  end

  # Process and send outgoing packets
  out_buf = Bytes.new(2048)
  while (out_size = quic_conn.send(out_buf)) > 0
    server_socket.send(out_buf[0, out_size], client_addr)
    puts "Server sent packet to client: #{out_size} bytes"
  end
end
