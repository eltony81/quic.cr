require "./spec_helper"

describe H3 do
  it "supports QPACK encoding and decoding" do
    headers = {
      ":method" => "GET",
      ":path" => "/index.html",
      "user-agent" => "quic.cr/h3",
    }
    encoded = H3::QPACK::Encoder.new.encode(headers)
    decoded = H3::QPACK::Decoder.new.decode(encoded)
    decoded.should eq(headers)
  end

  it "persistent QPACK encoder/decoder preserves headers across multiple calls" do
    # With a persistent encoder+decoder pair (same dynamic table state on both sides),
    # multiple rounds of encode/decode must produce consistent results.
    encoder = H3::QPACK::Encoder.new
    decoder = H3::QPACK::Decoder.new

    headers = {":status" => "200", "content-type" => "application/json", "x-custom" => "roundtrip-value"}

    # Encode twice and decode both; decoder must correctly resolve all references
    (1..3).each do
      encoded = encoder.encode(headers)
      # Simulate receiving encoder stream instructions at the decoder
      instr = encoder.encoder_stream_io.to_slice.dup
      encoder.encoder_stream_io.clear
      encoder.encoder_stream_io.rewind
      if instr.size > 0
        H3::QPACK::InstructionDecoder.new(decoder.dynamic_table).decode(IO::Memory.new(instr))
      end
      decoded = decoder.decode(encoded)
      decoded.should eq(headers)
    end
  end

  it "dynamic table reduces encoding size vs. all-literal encoding" do
    # Novel headers (not in static table) are encoded as literals when the dynamic
    # table has zero capacity, but as compact indexed references when capacity > 0.
    novel_headers = {"x-trace-id" => "abcdef1234567890", "x-region" => "us-east-1"}

    # With capacity = 0 (default): encoder falls back to literal field lines
    literal_encoder = H3::QPACK::Encoder.new  # capacity = 0 by default
    literal_encoded = literal_encoder.encode(novel_headers)

    # With capacity > 0: encoder inserts into dynamic table and uses indexed refs
    dynamic_encoder = H3::QPACK::Encoder.new
    dynamic_encoder.dynamic_table.set_capacity(4096_u64)
    dynamic_decoder = H3::QPACK::Decoder.new
    dynamic_decoder.dynamic_table.set_capacity(4096_u64)
    dynamic_encoded = dynamic_encoder.encode(novel_headers)

    # Process encoder stream instructions before decoding
    instr = dynamic_encoder.encoder_stream_io.to_slice.dup
    dynamic_encoder.encoder_stream_io.clear
    dynamic_encoder.encoder_stream_io.rewind
    H3::QPACK::InstructionDecoder.new(dynamic_decoder.dynamic_table).decode(IO::Memory.new(instr))

    decoded = dynamic_decoder.decode(dynamic_encoded)
    decoded.should eq(novel_headers)

    # Dynamic encoding must be more compact than all-literal encoding
    dynamic_encoded.size.should be < literal_encoded.size
  end

  it "Frame.decode uses provided QPACK decoder" do
    headers = {":status" => "200", "content-type" => "text/plain"}
    encoder = H3::QPACK::Encoder.new
    decoder = H3::QPACK::Decoder.new

    payload = encoder.encode(headers)
    io = IO::Memory.new
    QUIC::VarInt.write(io, H3::FrameType::HEADERS.to_u64)
    QUIC::VarInt.write(io, payload.size.to_u64)
    io.write(payload)
    io.rewind

    frame = H3::Frame.decode(io, decoder)
    frame.should be_a(H3::HeadersFrame)
    frame.as(H3::HeadersFrame).headers.should eq(headers)
  end

  it "serializes and deserializes HTTP/3 frames" do
    # DataFrame
    data_frame = H3::DataFrame.new("hello world".to_slice)
    io = IO::Memory.new
    data_frame.encode(io)
    io.rewind
    decoded_data = H3::Frame.decode(io)
    decoded_data.should be_a(H3::DataFrame)
    if decoded_data.is_a?(H3::DataFrame)
      String.new(decoded_data.data).should eq("hello world")
    end

    # HeadersFrame
    headers = {":status" => "200", "content-type" => "text/plain"}
    headers_frame = H3::HeadersFrame.new(headers)
    io2 = IO::Memory.new
    headers_frame.encode(io2)
    io2.rewind
    decoded_headers = H3::Frame.decode(io2)
    decoded_headers.should be_a(H3::HeadersFrame)
    if decoded_headers.is_a?(H3::HeadersFrame)
      decoded_headers.headers.should eq(headers)
    end

    # SettingsFrame
    settings_frame = H3::SettingsFrame.new
    settings_frame.settings[1_u64] = 4096_u64
    io3 = IO::Memory.new
    settings_frame.encode(io3)
    io3.rewind
    decoded_settings = H3::Frame.decode(io3)
    decoded_settings.should be_a(H3::SettingsFrame)
    if decoded_settings.is_a?(H3::SettingsFrame)
      decoded_settings.settings[1_u64].should eq(4096_u64)
    end
  end

  it "performs an end-to-end request-response flow" do
    config = QUIC::Config.new
    # Let's mock/use H3::Connection directly or H3::Client if we want. But the spec tests H3::Client and H3::Server request-response flow.
    # H3::Client.new expects (host, port, config) and starts a real socket loop.
    # If we want a unit/mock test of the end-to-end request-response flow without real UDP sockets, we can do it directly with H3::Connection.
    # Let's see: we have quic_client and quic_server.
    quic_client = QUIC::Connection.new(config, is_server: false)
    quic_server = QUIC::Connection.new(config, is_server: true)
    
    h3_client_conn = H3::Connection.new(quic_client)
    h3_server = H3::Server.new do |headers, body|
      headers[":method"].should eq("POST")
      headers[":path"].should eq("/greet")
      String.new(body).should eq("client message")
      
      resp_headers = {
        ":status" => "200",
        "content-type" => "text/plain",
      }
      {resp_headers, "hello from server".to_slice}
    end

    # 1. Client serializes request to client socket
    client_socket = MockSocket.new
    h3_client_conn.write_frame(client_socket, H3::HeadersFrame.new(
      {":method" => "POST", ":scheme" => "https", ":authority" => "localhost", ":path" => "/greet"}
    ))
    h3_client_conn.write_frame(client_socket, H3::DataFrame.new("client message".to_slice))
    
    # Get the payload sent by the client
    client_payload = client_socket.write_io.to_slice
    
    # 2. Server reads client payload and writes response
    server_socket = MockSocket.new(client_payload)
    h3_server.handle_request(h3_client_conn, server_socket)
    
    # Get the payload sent by the server
    server_payload = server_socket.write_io.to_slice
    
    # 3. Client processes server response
    final_socket = MockSocket.new(server_payload)
    resp_headers_frame = h3_client_conn.read_frame(final_socket)
    resp_headers_frame.should be_a(H3::HeadersFrame)
    
    # Read the data frame
    resp_data_frame = h3_client_conn.read_frame(final_socket)
    resp_data_frame.should be_a(H3::DataFrame)
    
    if resp_headers_frame.is_a?(H3::HeadersFrame) && resp_data_frame.is_a?(H3::DataFrame)
      resp_headers_frame.headers[":status"].should eq("200")
      String.new(resp_data_frame.data).should eq("hello from server")
    end
  end
end
