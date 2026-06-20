require "../src/quic"
require "socket"

# Reopen QUIC::Connection to expose handshake status
class QUIC::Connection
  def handshake_complete? : Bool
    @tls.handshake_complete?
  end
end

config = QUIC::Config.new
config.initial_max_data = 10_000_000_u64
config.initial_max_stream_data_bidi_local = 1_000_000_u64
config.initial_max_stream_data_bidi_remote = 1_000_000_u64
config.initial_max_streams_bidi = 100_u64
config.initial_max_streams_uni = 100_u64
config.initial_max_stream_data_uni = 1_000_000_u64
client = QUIC::Connection.new(config, is_server: false)
h3_client = H3::Client.new(client)

socket = UDPSocket.new
socket.connect("127.0.0.1", 4433)
puts "Connecting to HTTP/3 Server at udp://127.0.0.1:4433"

# Start TLS Handshake by sending client Initial
out_buf = Bytes.new(2048)
size = client.send(out_buf)
puts "Initial client.send generated packet size: #{size}"
if size > 0
  socket.send(out_buf[0, size])
  puts "Sent Initial packet to server."
end

buffer = Bytes.new(2048)
request_sent = false
stream : QUIC::StreamSocket? = nil

# Set read timeout to avoid hanging indefinitely if packets are dropped
socket.read_timeout = 2.seconds

loop do
  begin
    size, _server_addr = socket.receive(buffer)
    puts "Client received UDP packet from server: #{size} bytes"
    client.recv(buffer[0, size])
  rescue e : IO::TimeoutError
    # Timeout; check if we need to send anything
    puts "Client receive timed out."
  end

  # Process and send outgoing packets
  while (out_size = client.send(out_buf)) > 0
    socket.send(out_buf[0, out_size])
    puts "Client sent response/request packet: #{out_size} bytes"
  end

  if client.handshake_complete? && !request_sent
    puts "TLS Handshake complete! Sending HTTP/3 GET request..."
    headers = {
      ":method"     => "GET",
      ":path"       => "/",
      ":authority"  => "127.0.0.1",
      ":scheme"     => "https",
      "user-agent"  => "quic.cr/validate-client"
    }
    
    # Open request stream and write headers
    stream = h3_client.h3_conn.open_request_stream
    h3_client.h3_conn.write_frame(stream.not_nil!, H3::HeadersFrame.new(headers))
    h3_client.h3_conn.write_frame(stream.not_nil!, H3::DataFrame.new(Bytes.empty))
    request_sent = true
    
    # Send request packet
    while (out_size = client.send(out_buf)) > 0
      socket.send(out_buf[0, out_size])
      puts "Client sent HTTP/3 request packet: #{out_size} bytes"
    end
  end

  if request_sent && (s = stream)
    # Attempt to read response frames
    begin
      resp_headers_frame = h3_client.h3_conn.read_frame(s)
      if resp_headers_frame.is_a?(H3::HeadersFrame)
        puts "\n[Client Received Headers]:"
        p resp_headers_frame.headers
        
        # Read data frame
        resp_data_frame = h3_client.h3_conn.read_frame(s)
        if resp_data_frame.is_a?(H3::DataFrame)
          puts "\n[Client Received Body]:"
          puts String.new(resp_data_frame.data)
        end
        
        puts "Request completed successfully."
        break
      end
    rescue e
      # Data or frames not fully received yet, continue listening
    end
  end
end
