require "./spec_helper"

describe "QUIC Handshake" do
  it "client and server can exchange initial packets" do
    config = QUIC::Config.new
    client = QUIC::Connection.new(config, is_server: false)
    server = QUIC::Connection.new(config, is_server: true)
    
    # 1. Client sends Initial (ClientHello)
    client_buf = Bytes.new(2048)
    client_size = client.send(client_buf)
    client_size.should be > 0
    
    # 2. Server receives Initial
    server.recv(client_buf[0, client_size])
    
    # 3. Server sends Initial (ServerHello)
    server_buf = Bytes.new(2048)
    server_size = server.send(server_buf)
    server_size.should be > 0
    
    # 4. Client receives Initial
    client.recv(server_buf[0, server_size])
    
    # Handshake should be progressing
    # (Checking if internal TLS state is updated would require more exposure)
  end

  it "handles version negotiation" do
    config = QUIC::Config.new
    client = QUIC::Connection.new(config, is_server: false)
    
    # 1. Create a packet with an unsupported version (0x99999999)
    # Using LongHeaderPacket format
    unsupported_packet = QUIC::LongHeaderPacket.new(
      QUIC::PacketType::Initial,
      0x99999999_u32,
      Bytes.new(8, 1),
      Bytes.new(8, 2)
    )
    io = IO::Memory.new
    unsupported_packet.encode(io)
    
    # 2. Server receives packet and performs Version Negotiation.
    # We can simulate this using a server mock or invoking packet generation directly.
    negotiation = QUIC::VersionNegotiationPacket.new(
      unsupported_packet.scid,
      unsupported_packet.dcid,
      [0x00000001_u32]
    )
    negotiation_io = IO::Memory.new
    negotiation.encode(negotiation_io)
    
    # 3. Client receives Version Negotiation packet
    client.recv(negotiation_io.to_slice)
    client.version_negotiation_failed?.should be_true
    client.closed?.should be_true
  end

  it "handles Retry packet and extracts token" do
    config = QUIC::Config.new
    client = QUIC::Connection.new(config, is_server: false)
    
    # Send Initial to trigger setup
    buf = Bytes.new(2048)
    client.send(buf)
    
    # Construct a Retry packet from the server
    retry_token = "my_validation_token".to_slice
    retry_tag = Bytes.new(16, 0)
    retry_scid = "retry_scid_id".to_slice
    
    # Retry packet DCID is the client's SCID
    # Retry packet SCID is the server's chosen Retry SCID
    retry_packet = QUIC::RetryPacket.new(
      0x00000001_u32,
      client.scid.not_nil!,
      retry_scid,
      retry_token,
      retry_tag
    )
    
    io = IO::Memory.new
    retry_packet.encode(io)
    
    # Client receives the Retry packet
    client.recv(io.to_slice)
    
    # The client's DCID should now be updated to the server's retry_scid
    # We check if the token is included in the next generated client packet
    new_buf = Bytes.new(2048)
    size = client.send(new_buf)
    size.should be > 0
    
    # Parse only the header to verify the token is present
    new_io = IO::Memory.new(new_buf[0, size])
    first_byte = new_io.read_byte.not_nil!
    version = IO::ByteFormat::NetworkEndian.decode(UInt32, new_io)
    
    dcid_len = new_io.read_byte.not_nil!
    dcid = Bytes.new(dcid_len)
    new_io.read_fully(dcid)
    
    scid_len = new_io.read_byte.not_nil!
    scid = Bytes.new(scid_len)
    new_io.read_fully(scid)
    
    token_len = QUIC::VarInt.decode(new_io)
    token = Bytes.new(token_len)
    new_io.read_fully(token)
    
    token.should eq(retry_token)
  end
end
