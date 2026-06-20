require "../src/quic"

class QUIC::Connection
  def handshake_complete?
    @tls.handshake_complete?
  end
end

config = QUIC::Config.new
client = QUIC::Connection.new(config, is_server: false)
server = QUIC::Connection.new(config, is_server: true)

buf = Bytes.new(4096)

# We exchange packets in a loop until both are handshake_complete or one is closed.
iter = 0
while iter < 20 && (!client.handshake_complete? || !server.handshake_complete?)
  iter += 1
  puts "\n--- Iteration #{iter} ---"
  
  # Client -> Server
  if (client_len = client.send(buf)) > 0
    puts "Client sent #{client_len} bytes"
    server.recv(buf[0, client_len])
  end
  
  # Server -> Client
  if (server_len = server.send(buf)) > 0
    puts "Server sent #{server_len} bytes"
    client.recv(buf[0, server_len])
  end

  puts "Client handshake_complete? #{client.handshake_complete?} (closed? #{client.closed?})"
  puts "Server handshake_complete? #{server.handshake_complete?} (closed? #{server.closed?})"
  
  if client.closed? || server.closed?
    break
  end
end

puts "\nHandshake Loop Finished."
puts "Client complete: #{client.handshake_complete?}"
puts "Server complete: #{server.handshake_complete?}"
