require "socket"
require "./connection"
require "./qpack"

module H3
  class Client
    getter quic_conn : QUIC::Connection
    getter h3_conn : H3::Connection
    @socket : UDPSocket
    @remote_addr : Socket::IPAddress
    @connected : Bool = false
    
    def initialize(host : String, port : Int32, config : QUIC::Config)
      @remote_addr = Socket::IPAddress.new(host, port)
      @socket = UDPSocket.new
      @socket.connect(@remote_addr.address, @remote_addr.port)
      
      @quic_conn = QUIC::Connection.new(config, is_server: false)
      @h3_conn = H3::Connection.new(@quic_conn)
      
      # Receive loop
      spawn do
        receive_loop
      end
      
      # Send Initial QUIC packets
      pump_send
      
      # Wait for handshake completion or timeout
      select
      when @quic_conn.handshake_chan.receive
      when timeout(500.milliseconds)
      end
      @connected = true
      
      # Establish H3 Streams
      @h3_conn.open_uni_stream(0_u64) # Control Stream
      @h3_conn.open_uni_stream(0x02_u64) # Encoder Stream
      @h3_conn.open_uni_stream(0x03_u64) # Decoder Stream
      pump_send
    end

    def initialize(@quic_conn : QUIC::Connection)
      @h3_conn = H3::Connection.new(@quic_conn)
      @socket = UDPSocket.new
      @remote_addr = Socket::IPAddress.new("127.0.0.1", 0)
    end
    
    def get(path : String, headers = {} of String => String) : {Hash(String, String), Bytes, Hash(String, String)}
      request("GET", path, headers, nil)
    end
    
    def post(path : String, body : String | Bytes, headers = {} of String => String) : {Hash(String, String), Bytes, Hash(String, String)}
      request("POST", path, headers, body.is_a?(String) ? body.to_slice : body)
    end
    
    private def request(method : String, path : String, extra_headers : Hash(String, String), body : Bytes?) : {Hash(String, String), Bytes, Hash(String, String)}
      stream = @h3_conn.open_request_stream
      
      h = {
        ":method" => method,
        ":scheme" => "https",
        ":authority" => "#{@remote_addr.address}:#{@remote_addr.port}",
        ":path" => path,
        "user-agent" => "quic.cr/h3-client",
        "accept" => "*/*"
      }
      extra_headers.each { |k, v| h[k.downcase] = v }
      
      if body
        h["content-length"] = body.size.to_s
      end
      
      @h3_conn.write_frame(stream, HeadersFrame.new(h))
      
      if body
        @h3_conn.write_frame(stream, DataFrame.new(body))
      end
      
      if qs = @quic_conn.streams[stream.stream_id]?
        qs.close_local
      end
      
      pump_send
      
      # Read response
      resp_headers = {} of String => String
      resp_trailers = {} of String => String
      resp_body = IO::Memory.new
      recv_buf = IO::Memory.new
      
      # Set up stream channel to receive stream-specific packet updates without sleep polling
      stream_chan = Channel(Bool).new(5)
      @quic_conn.stream_chans[stream.stream_id] = stream_chan
      
      start_time = Time.instant
      while (Time.instant - start_time).total_seconds < 5.0
        if qs = @quic_conn.streams[stream.stream_id]?
          tmp_buf = Bytes.new(4096)
          bytes_read = qs.read(tmp_buf)
          if bytes_read > 0
            recv_buf.write(tmp_buf[0, bytes_read])
          end
          if qs.state == QUIC::StreamState::Closed || qs.state == QUIC::StreamState::HalfClosedRemote
            # Read any remaining data
            while (b_read = qs.read(tmp_buf)) > 0
              recv_buf.write(tmp_buf[0, b_read])
            end
            break
          end
        end
        
        # Block until there is new data on the stream or a brief timeout
        select
        when stream_chan.receive
        when timeout(100.milliseconds)
        end
      end
      @quic_conn.stream_chans.delete(stream.stream_id)
      
      recv_buf.rewind
      has_body = false
      while recv_buf.pos < recv_buf.size
        begin
          f = @h3_conn.read_frame(recv_buf)
          if f.is_a?(HeadersFrame)
            if has_body
              # Headers frame after body is considered trailer
              f.headers.each { |k, v| resp_trailers[k] = v }
            else
              resp_headers = f.headers
            end
          elsif f.is_a?(DataFrame)
            has_body = true
            resp_body.write(f.data)
          end
        rescue
          break
        end
      end
      
      {resp_headers, resp_body.to_slice, resp_trailers}
    end
    
    def close
      @quic_conn.close(0_u64, "Client shutdown")
      pump_send
      @socket.close
    end
    
    private def receive_loop
      buf = Bytes.new(65536)
      loop do
        break if @socket.closed?
        begin
          bytes_read, _ = @socket.receive(buf)
          if bytes_read > 0
            @quic_conn.recv(buf[0, bytes_read])
            pump_send
          end
        rescue e : Socket::Error
          break if @socket.closed?
        rescue e : Exception
          Log.trace { "Client receive error: #{e.message}" }
        end
      end
    end
    
    private def pump_send
      out_buf = Bytes.new(65536)
      loop do
        bytes_sent = @quic_conn.send(out_buf)
        break if bytes_sent == 0
        @socket.send(out_buf[0, bytes_sent])
      end
    end
  end
end
