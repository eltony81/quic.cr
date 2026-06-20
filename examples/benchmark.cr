require "benchmark"
require "http"
require "../src/quic"

# Mock socket for in-memory H3 testing (from h3_spec.cr)
class BenchmarkMockSocket < IO
  getter read_io : IO::Memory
  getter write_io : IO::Memory

  def initialize(read_bytes : Bytes = Bytes.empty)
    @read_io = IO::Memory.new(read_bytes)
    @write_io = IO::Memory.new
  end

  def read(slice : Bytes) : Int32
    @read_io.read(slice)
  end

  def write(slice : Bytes) : Nil
    @write_io.write(slice)
    nil
  end
end

# Setup HTTP/3 components
config = QUIC::Config.new
quic_client = QUIC::Connection.new(config, is_server: false)
h3_client = H3::Client.new(quic_client)
h3_server = H3::Server.new do |headers, body|
  resp_headers = {
    ":status" => "200",
    "content-type" => "text/plain",
  }
  {resp_headers, "hello world".to_slice}
end

# Headers to use in benchmark
h3_headers = {
  ":method" => "GET",
  ":path" => "/index.html",
  "user-agent" => "quic.cr/h3",
}

http_request = HTTP::Request.new("GET", "/index.html", HTTP::Headers{"User-Agent" => "crystal/http"})

# AEAD configuration to simulate TLS/QUIC packet encryption
aead = QUIC::Crypto::AEAD.new(Bytes.new(16, 1), Bytes.new(12, 2))
ad = Bytes.empty

puts "Running performance benchmark (Standard HTTP/1.1 vs HTTP over TLS (HTTPS) vs HTTP/3 over QUIC)..."

Benchmark.ips do |x|
  x.report("Standard HTTP/1.1 (Plain)") do
    io = IO::Memory.new
    
    # 1. Client writes request
    http_request.to_io(io)
    io.rewind
    
    # 2. Server reads request
    req = HTTP::Request.from_io(io).not_nil!
    
    # 3. Server writes response
    resp_io = IO::Memory.new
    resp = HTTP::Client::Response.new(200, "hello world", HTTP::Headers{"Content-Type" => "text/plain"})
    resp.to_io(resp_io)
    resp_io.rewind
    
    # 4. Client reads response
    HTTP::Client::Response.from_io(resp_io)
  end

  x.report("HTTP over TLS (HTTPS)") do
    # 1. Client writes request & encrypts payload
    io = IO::Memory.new
    http_request.to_io(io)
    plaintext_req = io.to_slice
    encrypted_req = aead.encrypt(ad, 0_u64, plaintext_req)
    
    # 2. Server decrypts & reads request
    decrypted_req = aead.decrypt(ad, 0_u64, encrypted_req)
    req = HTTP::Request.from_io(IO::Memory.new(decrypted_req)).not_nil!
    
    # 3. Server writes response & encrypts payload
    resp_io = IO::Memory.new
    resp = HTTP::Client::Response.new(200, "hello world", HTTP::Headers{"Content-Type" => "text/plain"})
    resp.to_io(resp_io)
    plaintext_resp = resp_io.to_slice
    encrypted_resp = aead.encrypt(ad, 1_u64, plaintext_resp)
    
    # 4. Client decrypts & reads response
    decrypted_resp = aead.decrypt(ad, 1_u64, encrypted_resp)
    HTTP::Client::Response.from_io(IO::Memory.new(decrypted_resp))
  end

  x.report("HTTP/3 over QUIC (with Encryption)") do
    # 1. Client serializes request frames to client socket & encrypts payload
    client_socket = BenchmarkMockSocket.new
    h3_client.h3_conn.write_frame(client_socket, H3::HeadersFrame.new(h3_headers))
    h3_client.h3_conn.write_frame(client_socket, H3::DataFrame.new("".to_slice))
    plaintext_req = client_socket.write_io.to_slice
    encrypted_req = aead.encrypt(ad, 0_u64, plaintext_req)
    
    # 2. Server decrypts, reads request frames and writes response frames & encrypts payload
    decrypted_req = aead.decrypt(ad, 0_u64, encrypted_req)
    server_socket = BenchmarkMockSocket.new(decrypted_req)
    h3_server.handle_request(h3_client.h3_conn, server_socket)
    plaintext_resp = server_socket.write_io.to_slice
    encrypted_resp = aead.encrypt(ad, 1_u64, plaintext_resp)
    
    # 3. Client decrypts and processes response frames
    decrypted_resp = aead.decrypt(ad, 1_u64, encrypted_resp)
    final_socket = BenchmarkMockSocket.new(decrypted_resp)
    resp_headers_frame = h3_client.h3_conn.read_frame(final_socket)
    resp_data_frame = h3_client.h3_conn.read_frame(final_socket)
  end
end
