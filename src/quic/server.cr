require "socket"

module QUIC
  class Server
    @socket : UDPSocket
    @connections = {} of String => Connection
    @config : Config
    property? require_address_validation : Bool = false

    def initialize(@config, address : String, port : Int32)
      @socket = UDPSocket.new
      @socket.bind(address, port)
    end

    def listen
      buffer = Bytes.new(2048)
      loop do
        size, client_addr = @socket.receive(buffer)
        data = buffer[0, size]
        
        begin
          io = IO::Memory.new(data)
          first_byte = io.read_byte.not_nil!
          is_long = (first_byte & 0x80) != 0
          
          version = 0x00000000_u32
          dcid = Bytes.empty
          scid = Bytes.empty
          token = Bytes.empty
          type_bits = 0x00_u8

          if is_long
            version = IO::ByteFormat::NetworkEndian.decode(UInt32, io)
            dcid_len = io.read_byte.not_nil!
            dcid = Bytes.new(dcid_len)
            io.read_fully(dcid)
            
            scid_len = io.read_byte.not_nil!
            scid = Bytes.new(scid_len)
            io.read_fully(scid)
            
            type_bits = (first_byte >> 4) & 0x03
            if type_bits == 0x00 # Initial
              token_len = VarInt.decode(io)
              token = Bytes.new(token_len)
              io.read_fully(token)
            end
          else
            # Short Header: fixed 8 bytes for this prototype
            dcid = Bytes.new(8)
            io.read_fully(dcid)
          end

          # 1. Version Negotiation (RFC 9000 Section 6)
          if is_long && version != 0x00000001_u32 && version != 0x00000000_u32
            negotiation = VersionNegotiationPacket.new(scid, dcid, [0x00000001_u32])
            out_buf = IO::Memory.new
            negotiation.encode(out_buf)
            @socket.send(out_buf.to_slice, client_addr)
            next
          end
          
          conn_key = dcid.hexstring
          conn = @connections[conn_key]?
          
          if conn.nil?
            if !is_long
              reset_first = 0x40_u8 | Random::Secure.rand(64).to_u8
              token = AddressValidation.stateless_reset_token(dcid)
              packet_bytes = Bytes.new(40)
              packet_bytes[0] = reset_first
              Random::Secure.random_bytes(packet_bytes[1, 23])
              packet_bytes[24, 16].copy_from(token)
              @socket.send(packet_bytes, client_addr)
              next
            end

            # New connection? (Only if Initial)
            if is_long && type_bits == 0x00
              # 2. Address Validation via Retry Packet (RFC 9000 Section 8)
              if @require_address_validation
                if token.empty? || !AddressValidation.validate_token(token, client_addr.ip.address)
                  retry_scid = Random::Secure.random_bytes(8)
                  new_token  = AddressValidation.generate_token(client_addr.ip.address)

                  # Build the Retry packet body (without tag) so we can compute the
                  # RFC 9001 Section 5.8 AES-128-GCM integrity tag over it.
                  partial_io = IO::Memory.new
                  RetryPacket.new(version, scid, retry_scid, new_token, Bytes.empty).encode_without_tag(partial_io)
                  # ODCID = dcid (original destination connection ID from client's first Initial)
                  retry_tag = AddressValidation.retry_integrity_tag(dcid, partial_io.to_slice)

                  retry_packet = RetryPacket.new(version, scid, retry_scid, new_token, retry_tag)
                  out_buf = IO::Memory.new
                  retry_packet.encode(out_buf)
                  @socket.send(out_buf.to_slice, client_addr)
                  next
                end
              end

              conn = Connection.new(@config, is_server: true)
              @connections[conn_key] = conn
            else
              next # Ignore unexpected packets
            end
          end
          
          conn.recv(data)
          
          # 3. Check for outgoing data
          out_buf = Bytes.new(2048)
          while (out_size = conn.send(out_buf)) > 0
            @socket.send(out_buf[0, out_size], client_addr)
          end
          
          # 4. Cleanup closed connections
          @connections.delete(conn_key) if conn.closed?
          
        rescue e
          Log.trace { "Server error: #{e.message}" }
        end
      end
    end
  end
end
