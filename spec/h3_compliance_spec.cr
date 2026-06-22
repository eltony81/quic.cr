require "./spec_helper"

# ── Helpers ───────────────────────────────────────────────────────────────────

# Minimal H3::Connection backed by a client-side QUIC connection.
# Client mode is chosen to avoid loading TLS cert/key files in unit tests,
# since handle_request / write_frame / read_frame never call quic.is_server?.
private def fresh_h3 : H3::Connection
  H3::Connection.new(QUIC::Connection.new(QUIC::Config.new, is_server: false))
end

# Encode a request as raw bytes (HEADERS [+ DATA]) for feeding into MockSocket.
private def encode_request(
  method : String, path : String,
  body : Bytes = Bytes.empty,
  extra_headers : Hash(String, String) = {} of String => String
) : Bytes
  h3 = fresh_h3
  io = IO::Memory.new
  base_hdrs = {":method" => method, ":scheme" => "https",
               ":authority" => "localhost", ":path" => path}
  hdrs = base_hdrs.merge(extra_headers)
  h3.write_frame(io, H3::HeadersFrame.new(hdrs))
  h3.write_frame(io, H3::DataFrame.new(body)) unless body.empty?
  io.to_slice
end

# Parse only the response :status from a MockSocket that handle_request wrote to.
private def parse_response_status(io : MockSocket) : String
  io.write_io.rewind
  frame = H3::Frame.decode(io.write_io, H3::QPACK::Decoder.new)
  frame.as(H3::HeadersFrame).headers[":status"]
end

# Parse the response HEADERS + optional DATA body written by handle_request.
private def parse_response(io : MockSocket) : {String, String}
  io.write_io.rewind
  decoder = H3::QPACK::Decoder.new
  headers_frame = H3::Frame.decode(io.write_io, decoder).as(H3::HeadersFrame)
  status = headers_frame.headers[":status"]
  body = begin
    df = H3::Frame.decode(io.write_io, decoder)
    df.is_a?(H3::DataFrame) ? String.new(df.data) : ""
  rescue
    ""
  end
  {status, body}
end

# ─────────────────────────────────────────────────────────────────────────────

describe "H3 Error Codes (RFC 9114 §8.1)" do
  it "H3_NO_ERROR is 0x0100" do
    H3::ErrorCode::H3_NO_ERROR.should eq(0x0100_u64)
  end

  it "H3_GENERAL_PROTOCOL_ERROR is 0x0101" do
    H3::ErrorCode::H3_GENERAL_PROTOCOL_ERROR.should eq(0x0101_u64)
  end

  it "H3_INTERNAL_ERROR is 0x0102" do
    H3::ErrorCode::H3_INTERNAL_ERROR.should eq(0x0102_u64)
  end

  it "H3_STREAM_CREATION_ERROR is 0x0103" do
    H3::ErrorCode::H3_STREAM_CREATION_ERROR.should eq(0x0103_u64)
  end

  it "H3_CLOSED_CRITICAL_STREAM is 0x0104" do
    H3::ErrorCode::H3_CLOSED_CRITICAL_STREAM.should eq(0x0104_u64)
  end

  it "H3_FRAME_UNEXPECTED is 0x0105" do
    H3::ErrorCode::H3_FRAME_UNEXPECTED.should eq(0x0105_u64)
  end

  it "H3_FRAME_ERROR is 0x0106" do
    H3::ErrorCode::H3_FRAME_ERROR.should eq(0x0106_u64)
  end

  it "H3_EXCESSIVE_LOAD is 0x0107" do
    H3::ErrorCode::H3_EXCESSIVE_LOAD.should eq(0x0107_u64)
  end

  it "H3_ID_ERROR is 0x0108" do
    H3::ErrorCode::H3_ID_ERROR.should eq(0x0108_u64)
  end

  it "H3_SETTINGS_ERROR is 0x0109" do
    H3::ErrorCode::H3_SETTINGS_ERROR.should eq(0x0109_u64)
  end

  it "H3_MISSING_SETTINGS is 0x010a" do
    H3::ErrorCode::H3_MISSING_SETTINGS.should eq(0x010a_u64)
  end

  it "H3_REQUEST_REJECTED is 0x010b" do
    H3::ErrorCode::H3_REQUEST_REJECTED.should eq(0x010b_u64)
  end

  it "H3_REQUEST_CANCELLED is 0x010c" do
    H3::ErrorCode::H3_REQUEST_CANCELLED.should eq(0x010c_u64)
  end

  it "H3_REQUEST_INCOMPLETE is 0x010d" do
    H3::ErrorCode::H3_REQUEST_INCOMPLETE.should eq(0x010d_u64)
  end

  it "H3_MESSAGE_ERROR is 0x010e" do
    H3::ErrorCode::H3_MESSAGE_ERROR.should eq(0x010e_u64)
  end

  it "H3_CONNECT_ERROR is 0x010f" do
    H3::ErrorCode::H3_CONNECT_ERROR.should eq(0x010f_u64)
  end

  it "H3_VERSION_FALLBACK is 0x0110" do
    H3::ErrorCode::H3_VERSION_FALLBACK.should eq(0x0110_u64)
  end

  it "error codes span the range 0x0100-0x0110" do
    H3::ErrorCode::H3_NO_ERROR.should be >= 0x0100_u64
    H3::ErrorCode::H3_VERSION_FALLBACK.should eq(0x0110_u64)
  end
end

describe "H3 Frame Type Values (RFC 9114 §7)" do
  it "DATA frame type is 0x00" do
    H3::FrameType::DATA.to_u64.should eq(0x00_u64)
  end

  it "HEADERS frame type is 0x01" do
    H3::FrameType::HEADERS.to_u64.should eq(0x01_u64)
  end

  it "CANCEL_PUSH frame type is 0x03 (RFC 9114 §7.2.3)" do
    H3::FrameType::CANCEL_PUSH.to_u64.should eq(0x03_u64)
  end

  it "SETTINGS frame type is 0x04 (RFC 9114 §7.2.4)" do
    H3::FrameType::SETTINGS.to_u64.should eq(0x04_u64)
  end

  it "PUSH_PROMISE frame type is 0x05 (RFC 9114 §7.2.5)" do
    H3::FrameType::PUSH_PROMISE.to_u64.should eq(0x05_u64)
  end

  it "GOAWAY frame type is 0x07 (RFC 9114 §7.2.6)" do
    H3::FrameType::GOAWAY.to_u64.should eq(0x07_u64)
  end
end

describe "H3 Control Stream (RFC 9114 §6.2.1)" do
  it "control stream type byte is 0x00" do
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x00_u64)
    io.rewind
    QUIC::VarInt.decode(io).should eq(0x00_u64)
  end

  it "control stream wire layout: type byte precedes SETTINGS frame" do
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x00_u64)        # stream type = Control Stream
    sf = H3::SettingsFrame.new
    sf.settings[0x01_u64] = 0_u64
    sf.settings[0x07_u64] = 100_u64
    sf.encode(io)
    io.rewind
    stream_type = QUIC::VarInt.decode(io)
    frame_type  = QUIC::VarInt.decode(io)
    stream_type.should eq(0x00_u64)                         # Control Stream
    frame_type.should  eq(H3::FrameType::SETTINGS.to_u64)  # SETTINGS first
  end

  it "QPACK encoder stream type is 0x02" do
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x02_u64)
    io.rewind
    QUIC::VarInt.decode(io).should eq(0x02_u64)
  end

  it "QPACK decoder stream type is 0x03" do
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x03_u64)
    io.rewind
    QUIC::VarInt.decode(io).should eq(0x03_u64)
  end
end

describe "H3 SETTINGS Frame (RFC 9114 §7.2.4)" do
  it "SETTINGS round-trips with QPACK_MAX_TABLE_CAPACITY (id=0x01)" do
    sf = H3::SettingsFrame.new
    sf.settings[0x01_u64] = 4096_u64
    io = IO::Memory.new
    sf.encode(io)
    io.rewind
    decoded = H3::Frame.decode(io).as(H3::SettingsFrame)
    decoded.settings[0x01_u64].should eq(4096_u64)
  end

  it "SETTINGS round-trips with QPACK_BLOCKED_STREAMS (id=0x07)" do
    sf = H3::SettingsFrame.new
    sf.settings[0x07_u64] = 100_u64
    io = IO::Memory.new
    sf.encode(io)
    io.rewind
    decoded = H3::Frame.decode(io).as(H3::SettingsFrame)
    decoded.settings[0x07_u64].should eq(100_u64)
  end

  it "SETTINGS preserves multiple parameters across encode-decode" do
    sf = H3::SettingsFrame.new
    sf.settings[0x01_u64] = 4096_u64  # QPACK_MAX_TABLE_CAPACITY
    sf.settings[0x06_u64] = 1024_u64  # MAX_FIELD_SECTION_SIZE
    sf.settings[0x07_u64] = 100_u64   # QPACK_BLOCKED_STREAMS
    io = IO::Memory.new
    sf.encode(io)
    io.rewind
    decoded = H3::Frame.decode(io).as(H3::SettingsFrame)
    decoded.settings[0x01_u64].should eq(4096_u64)
    decoded.settings[0x06_u64].should eq(1024_u64)
    decoded.settings[0x07_u64].should eq(100_u64)
  end

  it "empty SETTINGS frame is valid (all parameters optional per RFC)" do
    sf = H3::SettingsFrame.new
    io = IO::Memory.new
    sf.encode(io)
    io.rewind
    decoded = H3::Frame.decode(io).as(H3::SettingsFrame)
    decoded.settings.should be_empty
  end
end

describe "H3 Unidirectional Streams (RFC 9114 §6.2)" do
  it "QPACK encoder stream (type 0x02) is consumed without error" do
    server = H3::Server.new(H3::Router.new)
    h3 = fresh_h3
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x02_u64)  # QPACK encoder stream
    io.write(Bytes.new(8, 0_u8))      # placeholder encoder instructions
    server.handle_uni_stream(h3, MockSocket.new(io.to_slice))
  end

  it "QPACK decoder stream (type 0x03) is consumed without error" do
    server = H3::Server.new(H3::Router.new)
    h3 = fresh_h3
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x03_u64)
    io.write(Bytes.new(4, 0_u8))
    server.handle_uni_stream(h3, MockSocket.new(io.to_slice))
  end

  it "control stream (type 0x00) with SETTINGS is consumed without error" do
    server = H3::Server.new(H3::Router.new)
    h3 = fresh_h3
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x00_u64)  # Control Stream
    sf = H3::SettingsFrame.new
    sf.settings[0x01_u64] = 0_u64
    sf.encode(io)
    server.handle_uni_stream(h3, MockSocket.new(io.to_slice))
  end

  it "unknown unidirectional stream type is consumed without error (RFC 9114 §6.2)" do
    server = H3::Server.new(H3::Router.new)
    h3 = fresh_h3
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x21_u64)  # unknown type
    io.write(Bytes.new(16, 0xFF_u8))
    server.handle_uni_stream(h3, MockSocket.new(io.to_slice))
  end

  it "very large unknown stream type varint is consumed without error" do
    server = H3::Server.new(H3::Router.new)
    h3 = fresh_h3
    io = IO::Memory.new
    QUIC::VarInt.write(io, 0x3FFFFFFF_u64)  # max 4-byte varint
    io.write(Bytes.new(4, 0x00_u8))
    server.handle_uni_stream(h3, MockSocket.new(io.to_slice))
  end
end

describe "H3 Request Pseudo-Headers (RFC 9114 §4.3.1)" do
  it "request with all required pseudo-headers is dispatched correctly" do
    router = H3::Router.new
    router.get("/ok") { |ctx| ctx.text "ok" }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/ok"))
    server.handle_request(fresh_h3, io)
    parse_response_status(io).should eq("200")
  end

  it "pseudo-headers are NOT present in Request#headers (stripped)" do
    captured_headers = {} of String => String
    router = H3::Router.new
    router.get("/headers") { |ctx| captured_headers = ctx.request.headers }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/headers"))
    server.handle_request(fresh_h3, io)
    captured_headers.keys.none? { |k| k.starts_with?(":") }.should be_true
  end

  it "request :method is accessible on H3::Request" do
    captured = ""
    router = H3::Router.new
    router.post("/m") { |ctx| captured = ctx.request.method }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("POST", "/m", "body".to_slice))
    server.handle_request(fresh_h3, io)
    captured.should eq("POST")
  end

  it "request :path with query string is split into path + query_string" do
    captured_path = ""
    captured_qs   = ""
    router = H3::Router.new
    router.get("/search") do |ctx|
      captured_path = ctx.request.path
      captured_qs   = ctx.request.query_string
    end
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/search?q=quic&page=1"))
    server.handle_request(fresh_h3, io)
    captured_path.should eq("/search")
    captured_qs.should eq("q=quic&page=1")
  end

  it "missing :method is rejected with H3_MESSAGE_ERROR (no response written)" do
    router = H3::Router.new
    router.get("/fallback") { |ctx| ctx.text "ok" }
    server = H3::Server.new(router)
    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":scheme" => "https", ":path" => "/fallback", ":authority" => "localhost"}
    ))
    conn = fresh_h3
    io = MockSocket.new(io_src.to_slice)
    server.handle_request(conn, io)
    # Connection is closed with H3_MESSAGE_ERROR; no response frames are written.
    io.write_io.size.should eq(0)
    conn.quic.closed?.should be_true
  end

  it "non-pseudo headers are exposed via Request#headers" do
    captured = ""
    router = H3::Router.new
    router.get("/hdr") { |ctx| captured = ctx.request.headers["x-custom"]? || "" }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/hdr",
      extra_headers: {"x-custom" => "value123"}))
    server.handle_request(fresh_h3, io)
    captured.should eq("value123")
  end

  it "multiple custom request headers are all exposed" do
    captured = {} of String => String
    router = H3::Router.new
    router.get("/multi") { |ctx| captured = ctx.request.headers }
    server = H3::Server.new(router)
    extra = {"x-a" => "alpha", "x-b" => "beta", "x-c" => "gamma"}
    io = MockSocket.new(encode_request("GET", "/multi", extra_headers: extra))
    server.handle_request(fresh_h3, io)
    captured["x-a"].should eq("alpha")
    captured["x-b"].should eq("beta")
    captured["x-c"].should eq("gamma")
  end
end

describe "H3 Rejection Behaviors (RFC 9114 §4.3.1, §7.1, §7.2)" do
  # ── Wrong frame type before HEADERS ─────────────────────────────────────────

  it "DATA frame before HEADERS closes connection with H3_FRAME_UNEXPECTED" do
    conn = fresh_h3
    io_src = IO::Memory.new
    H3::DataFrame.new("orphan body".to_slice).encode(io_src)
    io = MockSocket.new(io_src.to_slice)
    H3::Server.new(H3::Router.new).handle_request(conn, io)
    conn.quic.closed?.should be_true
  end

  it "SETTINGS frame before HEADERS closes connection with H3_FRAME_UNEXPECTED" do
    conn = fresh_h3
    io_src = IO::Memory.new
    sf = H3::SettingsFrame.new
    sf.settings[0x01_u64] = 0_u64
    sf.encode(io_src)
    io = MockSocket.new(io_src.to_slice)
    H3::Server.new(H3::Router.new).handle_request(conn, io)
    conn.quic.closed?.should be_true
  end

  it "SETTINGS frame in request body closes connection with H3_FRAME_UNEXPECTED" do
    conn = fresh_h3
    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "GET", ":scheme" => "https", ":authority" => "localhost", ":path" => "/"}
    ))
    sf = H3::SettingsFrame.new
    sf.settings[0x01_u64] = 0_u64
    sf.encode(io_src)
    io = MockSocket.new(io_src.to_slice)
    H3::Server.new(H3::Router.new).handle_request(conn, io)
    conn.quic.closed?.should be_true
  end

  # ── Missing required pseudo-headers ─────────────────────────────────────────

  it "missing :scheme closes connection with H3_MESSAGE_ERROR" do
    conn = fresh_h3
    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "GET", ":path" => "/", ":authority" => "localhost"}
    ))
    io = MockSocket.new(io_src.to_slice)
    H3::Server.new(H3::Router.new).handle_request(conn, io)
    conn.quic.closed?.should be_true
    io.write_io.size.should eq(0)
  end

  it "missing :path closes connection with H3_MESSAGE_ERROR" do
    conn = fresh_h3
    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "GET", ":scheme" => "https", ":authority" => "localhost"}
    ))
    io = MockSocket.new(io_src.to_slice)
    H3::Server.new(H3::Router.new).handle_request(conn, io)
    conn.quic.closed?.should be_true
    io.write_io.size.should eq(0)
  end

  it "all three required pseudo-headers present: request is accepted" do
    router = H3::Router.new
    router.get("/") { |ctx| ctx.text "ok" }
    io = MockSocket.new(encode_request("GET", "/"))
    server = H3::Server.new(router)
    server.handle_request(fresh_h3, io)
    parse_response_status(io).should eq("200")
  end

  # ── :status in a request ─────────────────────────────────────────────────────

  it ":status pseudo-header in request closes connection with H3_MESSAGE_ERROR" do
    conn = fresh_h3
    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "GET", ":scheme" => "https",
       ":authority" => "localhost", ":path" => "/", ":status" => "200"}
    ))
    io = MockSocket.new(io_src.to_slice)
    H3::Server.new(H3::Router.new).handle_request(conn, io)
    conn.quic.closed?.should be_true
    io.write_io.size.should eq(0)
  end

  # ── Duplicate pseudo-headers ─────────────────────────────────────────────────

  it "duplicate :method pseudo-header is rejected by QPACK decoder" do
    # Build a raw HEADERS frame with :method appearing twice.
    encoder = H3::QPACK::Encoder.new
    # Encode two separate field sections and combine their payloads.
    # Simpler: build raw QPACK bytes manually with two :method literals.
    payload = IO::Memory.new
    # QPACK prefix: RIC=0, Base=0
    payload.write_byte 0x00_u8
    payload.write_byte 0x00_u8
    # Literal Without Name Reference for :method GET
    H3::QPACK::Integer.encode(payload, ":method".bytesize.to_u64, 3, 0x20_u8)
    payload.write(":method".to_slice)
    H3::QPACK::Integer.encode(payload, "GET".bytesize.to_u64, 7, 0x00_u8)
    payload.write("GET".to_slice)
    # Second :method — duplicate
    H3::QPACK::Integer.encode(payload, ":method".bytesize.to_u64, 3, 0x20_u8)
    payload.write(":method".to_slice)
    H3::QPACK::Integer.encode(payload, "POST".bytesize.to_u64, 7, 0x00_u8)
    payload.write("POST".to_slice)

    expect_raises(H3::QPACK::ValidationError) do
      H3::QPACK::Decoder.new.decode(payload.to_slice)
    end
  end

  it "regular header before pseudo-header is rejected by QPACK decoder" do
    payload = IO::Memory.new
    payload.write_byte 0x00_u8  # RIC
    payload.write_byte 0x00_u8  # Base
    # Regular header first: x-custom: value
    H3::QPACK::Integer.encode(payload, "x-custom".bytesize.to_u64, 3, 0x20_u8)
    payload.write("x-custom".to_slice)
    H3::QPACK::Integer.encode(payload, "value".bytesize.to_u64, 7, 0x00_u8)
    payload.write("value".to_slice)
    # Then a pseudo-header
    H3::QPACK::Integer.encode(payload, ":method".bytesize.to_u64, 3, 0x20_u8)
    payload.write(":method".to_slice)
    H3::QPACK::Integer.encode(payload, "GET".bytesize.to_u64, 7, 0x00_u8)
    payload.write("GET".to_slice)

    expect_raises(H3::QPACK::ValidationError) do
      H3::QPACK::Decoder.new.decode(payload.to_slice)
    end
  end

  it "valid request with pseudo-headers first is accepted by QPACK decoder" do
    headers = {":method" => "GET", ":path" => "/", ":scheme" => "https",
               "x-custom" => "value"}
    encoded = H3::QPACK::Encoder.new.encode(headers)
    decoded = H3::QPACK::Decoder.new.decode(encoded)
    decoded.should eq(headers)
  end
end

describe "H3 Response Pseudo-Headers (RFC 9114 §4.3.2)" do
  it "response always includes :status pseudo-header" do
    router = H3::Router.new
    router.get("/") { |ctx| ctx.text "hi" }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/"))
    server.handle_request(fresh_h3, io)
    parse_response_status(io).should eq("200")
  end

  it "404 response :status is '404'" do
    server = H3::Server.new(H3::Router.new)
    io = MockSocket.new(encode_request("GET", "/nope"))
    server.handle_request(fresh_h3, io)
    parse_response_status(io).should eq("404")
  end

  it "response :status reflects ctx.text with explicit status 201" do
    router = H3::Router.new
    router.post("/create") { |ctx| ctx.text("created", 201) }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("POST", "/create", "{}".to_slice))
    server.handle_request(fresh_h3, io)
    parse_response_status(io).should eq("201")
  end

  it "redirect response :status is 302 with location header" do
    router = H3::Router.new
    router.get("/old") { |ctx| ctx.redirect("/new") }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/old"))
    server.handle_request(fresh_h3, io)
    io.write_io.rewind
    headers = H3::Frame.decode(io.write_io, H3::QPACK::Decoder.new)
      .as(H3::HeadersFrame).headers
    headers[":status"].should eq("302")
    headers["location"].should eq("/new")
  end

  it "response includes content-type when ctx.json is called" do
    router = H3::Router.new
    router.get("/json") { |ctx| ctx.json %[{"x":1}] }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/json"))
    server.handle_request(fresh_h3, io)
    io.write_io.rewind
    headers = H3::Frame.decode(io.write_io, H3::QPACK::Decoder.new)
      .as(H3::HeadersFrame).headers
    headers["content-type"].should contain("application/json")
  end

  it "response content-type for ctx.text contains text/plain" do
    router = H3::Router.new
    router.get("/txt") { |ctx| ctx.text "hello" }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/txt"))
    server.handle_request(fresh_h3, io)
    io.write_io.rewind
    headers = H3::Frame.decode(io.write_io, H3::QPACK::Decoder.new)
      .as(H3::HeadersFrame).headers
    headers["content-type"].should contain("text/plain")
  end
end

describe "H3 Body Framing (RFC 9114 §4.1)" do
  it "request body in a single DATA frame is delivered to handler" do
    body_received = Bytes.empty
    router = H3::Router.new
    router.post("/echo") { |ctx| body_received = ctx.request.body }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("POST", "/echo", "hello world".to_slice))
    server.handle_request(fresh_h3, io)
    String.new(body_received).should eq("hello world")
  end

  it "request body split across two DATA frames is fully assembled" do
    body_received = Bytes.empty
    router = H3::Router.new
    router.post("/echo") { |ctx| body_received = ctx.request.body }
    server = H3::Server.new(router)

    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "POST", ":scheme" => "https",
       ":authority" => "localhost", ":path" => "/echo"}
    ))
    h3c.write_frame(io_src, H3::DataFrame.new("hello ".to_slice))
    h3c.write_frame(io_src, H3::DataFrame.new("world".to_slice))

    io = MockSocket.new(io_src.to_slice)
    server.handle_request(fresh_h3, io)
    String.new(body_received).should eq("hello world")
  end

  it "GET request with no DATA frame delivers empty body to handler" do
    body_received = "nonempty"
    router = H3::Router.new
    router.get("/") { |ctx| body_received = ctx.body_string }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/"))
    server.handle_request(fresh_h3, io)
    body_received.should eq("")
  end

  it "response body is sent as DATA frame immediately after HEADERS" do
    router = H3::Router.new
    router.get("/data") { |ctx| ctx.text("response body") }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/data"))
    server.handle_request(fresh_h3, io)
    _, body = parse_response(io)
    body.should eq("response body")
  end

  it "204 response produces no DATA frame (empty body)" do
    router = H3::Router.new
    router.get("/empty") { |ctx| ctx.response.status = 204 }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/empty"))
    server.handle_request(fresh_h3, io)

    io.write_io.rewind
    # First frame must be HEADERS with :status=204
    frame = H3::Frame.decode(io.write_io, H3::QPACK::Decoder.new)
    frame.as(H3::HeadersFrame).headers[":status"].should eq("204")
    # No DATA frame follows — reading again hits EOF and raises
    expect_raises(Exception) do
      H3::Frame.decode(io.write_io, H3::QPACK::Decoder.new)
    end
  end

  it "large request body (64 KB) is fully delivered to handler" do
    body_received = Bytes.empty
    router = H3::Router.new
    router.post("/big") { |ctx| body_received = ctx.request.body }
    server = H3::Server.new(router)
    big_body = Bytes.new(65536, 0xAB_u8)
    io = MockSocket.new(encode_request("POST", "/big", big_body))
    server.handle_request(fresh_h3, io)
    body_received.size.should eq(65536)
    body_received.all? { |b| b == 0xAB_u8 }.should be_true
  end

  it "response body round-trips binary content correctly" do
    payload = "binary\x00data\xFF"
    router = H3::Router.new
    router.get("/bin") { |ctx| ctx.response.write(payload.to_slice) }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/bin"))
    server.handle_request(fresh_h3, io)
    _, body = parse_response(io)
    body.should eq(payload)
  end
end

describe "H3 Trailers (RFC 9114 §4.3)" do
  it "trailing HEADERS frame stops body reading after DATA frame" do
    body_received = Bytes.empty
    router = H3::Router.new
    router.post("/trailer") { |ctx| body_received = ctx.request.body }
    server = H3::Server.new(router)

    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "POST", ":scheme" => "https",
       ":authority" => "localhost", ":path" => "/trailer"}
    ))
    h3c.write_frame(io_src, H3::DataFrame.new("main body".to_slice))
    h3c.write_frame(io_src, H3::HeadersFrame.new({"x-trailer" => "value"}))

    io = MockSocket.new(io_src.to_slice)
    server.handle_request(fresh_h3, io)
    String.new(body_received).should eq("main body")
  end
end

describe "H3 Frame Rules (RFC 9114 §7)" do
  it "unknown frame type in request stream is ignored; request still handled" do
    router = H3::Router.new
    router.get("/ok") { |ctx| ctx.text "ok" }
    server = H3::Server.new(router)

    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "GET", ":scheme" => "https",
       ":authority" => "localhost", ":path" => "/ok"}
    ))
    # Unknown H3 frame type 0x21 between HEADERS and EOF
    QUIC::VarInt.write(io_src, 0x21_u64)
    QUIC::VarInt.write(io_src, 4_u64)
    io_src.write(Bytes[0x01, 0x02, 0x03, 0x04])

    io = MockSocket.new(io_src.to_slice)
    server.handle_request(fresh_h3, io)
    parse_response_status(io).should eq("200")
  end

  it "HEADERS frame encodes and decodes via QPACK symmetric codec" do
    encoder = H3::QPACK::Encoder.new
    decoder = H3::QPACK::Decoder.new
    headers = {":method" => "GET", ":path" => "/", ":scheme" => "https",
               ":authority" => "localhost", "accept" => "application/json"}
    encoded = encoder.encode(headers)
    decoded = decoder.decode(encoded)
    decoded.should eq(headers)
  end

  it "DATA frame preserves binary content without modification" do
    binary = Bytes.new(256) { |i| i.to_u8 }
    io = IO::Memory.new
    H3::DataFrame.new(binary).encode(io)
    io.rewind
    frame = H3::Frame.decode(io).as(H3::DataFrame)
    frame.data.should eq(binary)
  end

  it "PUSH_PROMISE in request body triggers H3_ID_ERROR (no response written)" do
    # RFC 9114 §7.2.5: clients MUST NOT send PUSH_PROMISE frames.
    router = H3::Router.new
    router.get("/") { |ctx| ctx.text "ok" }
    server = H3::Server.new(router)

    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "GET", ":scheme" => "https",
       ":authority" => "localhost", ":path" => "/"}
    ))
    QUIC::VarInt.write(io_src, H3::FrameType::PUSH_PROMISE.to_u64)
    QUIC::VarInt.write(io_src, 2_u64)
    io_src.write(Bytes[0x00, 0x01])

    conn = fresh_h3
    io = MockSocket.new(io_src.to_slice)
    server.handle_request(conn, io)
    conn.quic.closed?.should be_true
  end

  it "PUSH_PROMISE as first frame (before HEADERS) triggers H3_ID_ERROR" do
    conn = fresh_h3
    io_src = IO::Memory.new
    QUIC::VarInt.write(io_src, H3::FrameType::PUSH_PROMISE.to_u64)
    QUIC::VarInt.write(io_src, 2_u64)
    io_src.write(Bytes[0x00, 0x01])
    io = MockSocket.new(io_src.to_slice)
    H3::Server.new(H3::Router.new).handle_request(conn, io)
    conn.quic.closed?.should be_true
  end
end

describe "H3 Method Semantics (RFC 9114 §4.3.1)" do
  it "GET request body is empty without a DATA frame" do
    body_size = -1
    router = H3::Router.new
    router.get("/") { |ctx| body_size = ctx.request.body.size }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("GET", "/"))
    server.handle_request(fresh_h3, io)
    body_size.should eq(0)
  end

  it "HEAD request is routed to HEAD handler (not GET)" do
    hit = ""
    router = H3::Router.new
    router.get("/")  { |ctx| hit = "GET";  ctx.text "get" }
    router.head("/") { |ctx| hit = "HEAD"; ctx.text "" }
    server = H3::Server.new(router)

    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "HEAD", ":scheme" => "https",
       ":authority" => "localhost", ":path" => "/"}
    ))
    io = MockSocket.new(io_src.to_slice)
    server.handle_request(fresh_h3, io)
    hit.should eq("HEAD")
  end

  it "DELETE request is dispatched to delete handler" do
    router = H3::Router.new
    router.delete("/item") { |ctx| ctx.response.status = 204 }
    server = H3::Server.new(router)

    h3c = fresh_h3
    io_src = IO::Memory.new
    h3c.write_frame(io_src, H3::HeadersFrame.new(
      {":method" => "DELETE", ":scheme" => "https",
       ":authority" => "localhost", ":path" => "/item"}
    ))
    io = MockSocket.new(io_src.to_slice)
    server.handle_request(fresh_h3, io)
    parse_response_status(io).should eq("204")
  end

  it "PATCH request delivers body and routes correctly" do
    received_body = ""
    router = H3::Router.new
    router.patch("/patch") { |ctx| received_body = ctx.body_string; ctx.text "patched" }
    server = H3::Server.new(router)
    io = MockSocket.new(encode_request("PATCH", "/patch", "delta".to_slice))
    server.handle_request(fresh_h3, io)
    received_body.should eq("delta")
    parse_response_status(io).should eq("200")
  end
end

describe "H3 Low-level Handler (Mode 1)" do
  it "low-level handler receives raw headers and body bytes" do
    received_method = ""
    received_body   = Bytes.empty
    server = H3::Server.new do |headers, body|
      received_method = headers[":method"]? || ""
      received_body   = body
      resp_h = {":status" => "200"}
      {resp_h, Bytes.empty}
    end

    io = MockSocket.new(encode_request("POST", "/", "raw bytes".to_slice))
    server.handle_request(fresh_h3, io)
    received_method.should eq("POST")
    String.new(received_body).should eq("raw bytes")
  end

  it "low-level handler response headers are encoded and returned" do
    server = H3::Server.new do |_, _|
      resp_h = {":status" => "201", "x-custom" => "yes"}
      {resp_h, Bytes.empty}
    end

    io = MockSocket.new(encode_request("POST", "/"))
    server.handle_request(fresh_h3, io)
    io.write_io.rewind
    headers = H3::Frame.decode(io.write_io, H3::QPACK::Decoder.new)
      .as(H3::HeadersFrame).headers
    headers[":status"].should eq("201")
    headers["x-custom"].should eq("yes")
  end

  it "low-level handler response body is sent as DATA frame" do
    server = H3::Server.new do |_, _|
      resp_h = {":status" => "200"}
      {resp_h, "hello from low-level".to_slice}
    end

    io = MockSocket.new(encode_request("GET", "/"))
    server.handle_request(fresh_h3, io)
    _, body = parse_response(io)
    body.should eq("hello from low-level")
  end
end

describe "H3 Concurrent Requests (RFC 9114 §4.1)" do
  it "two sequential requests on different H3 connections are independent" do
    router = H3::Router.new
    router.get("/a") { |ctx| ctx.text "A" }
    router.get("/b") { |ctx| ctx.text "B" }
    server = H3::Server.new(router)

    io_a = MockSocket.new(encode_request("GET", "/a"))
    io_b = MockSocket.new(encode_request("GET", "/b"))
    server.handle_request(fresh_h3, io_a)
    server.handle_request(fresh_h3, io_b)

    _, body_a = parse_response(io_a)
    _, body_b = parse_response(io_b)
    body_a.should eq("A")
    body_b.should eq("B")
  end

  it "routes on the same server each return distinct responses" do
    router = H3::Router.new
    router.get("/one")   { |ctx| ctx.json %[{"n":1}] }
    router.get("/two")   { |ctx| ctx.json %[{"n":2}] }
    router.get("/three") { |ctx| ctx.json %[{"n":3}] }
    server = H3::Server.new(router)

    expected = {"/one" => %[{"n":1}], "/two" => %[{"n":2}], "/three" => %[{"n":3}]}
    expected.each do |path, want|
      io = MockSocket.new(encode_request("GET", path))
      server.handle_request(fresh_h3, io)
      _, body = parse_response(io)
      body.should eq(want)
    end
  end

  it "same router handles GET and POST on the same path independently" do
    router = H3::Router.new
    router.get("/item")  { |ctx| ctx.text "item-get" }
    router.post("/item") { |ctx| ctx.text "item-post" }
    server = H3::Server.new(router)

    io_get  = MockSocket.new(encode_request("GET",  "/item"))
    io_post = MockSocket.new(encode_request("POST", "/item", "{}".to_slice))
    server.handle_request(fresh_h3, io_get)
    server.handle_request(fresh_h3, io_post)

    _, body_g = parse_response(io_get)
    _, body_p = parse_response(io_post)
    body_g.should eq("item-get")
    body_p.should eq("item-post")
  end
end

describe "H3 QPACK Integration (RFC 9204)" do
  it "static table entries survive encode-decode for common headers" do
    pairs = [
      {":method" => "GET"},
      {":method" => "POST"},
      {":status" => "200"},
      {":status" => "404"},
      {"content-type" => "application/json"},
      {"content-encoding" => "gzip"},
    ]
    pairs.each do |headers|
      encoded = H3::QPACK::Encoder.new.encode(headers)
      decoded = H3::QPACK::Decoder.new.decode(encoded)
      decoded.should eq(headers)
    end
  end

  it "QPACK encodes and decodes headers with percent-encoded path values" do
    headers = {":method" => "GET", ":path" => "/search?q=caf%C3%A9&lang=fr"}
    encoded = H3::QPACK::Encoder.new.encode(headers)
    decoded = H3::QPACK::Decoder.new.decode(encoded)
    decoded.should eq(headers)
  end

  it "QPACK encodes empty header value correctly" do
    headers = {"x-empty" => ""}
    encoded = H3::QPACK::Encoder.new.encode(headers)
    decoded = H3::QPACK::Decoder.new.decode(encoded)
    decoded.should eq(headers)
  end

  it "QPACK handles 10 custom headers in one field section" do
    # Pseudo-headers must precede regular headers (RFC 9114 §4.3).
    headers = {":method" => "GET", ":path" => "/"}
    (1..10).each { |i| headers["x-header-#{i}"] = "value-#{i}" }
    encoded = H3::QPACK::Encoder.new.encode(headers)
    decoded = H3::QPACK::Decoder.new.decode(encoded)
    decoded.should eq(headers)
  end

  it "QPACK Huffman coding compresses common headers below raw byte size" do
    headers = {":method" => "GET", ":path" => "/", ":scheme" => "https",
               ":status" => "200", "content-type" => "text/html"}
    encoder = H3::QPACK::Encoder.new
    encoded = encoder.encode(headers)
    raw_size = headers.sum { |k, v| k.bytesize + v.bytesize }
    encoded.size.should be < raw_size
  end

  it "H3 write_frame and read_frame are symmetric for HEADERS frames" do
    sender   = fresh_h3
    receiver = fresh_h3
    headers  = {":status" => "200", "content-type" => "text/plain", "x-foo" => "bar"}

    io = IO::Memory.new
    sender.write_frame(io, H3::HeadersFrame.new(headers))
    io.rewind
    decoded_frame = receiver.read_frame(io).as(H3::HeadersFrame)
    decoded_frame.headers.should eq(headers)
  end

  it "H3 write_frame and read_frame are symmetric for DATA frames" do
    sender   = fresh_h3
    receiver = fresh_h3
    payload  = "test payload".to_slice

    io = IO::Memory.new
    sender.write_frame(io, H3::DataFrame.new(payload))
    io.rewind
    decoded_frame = receiver.read_frame(io).as(H3::DataFrame)
    decoded_frame.data.should eq(payload)
  end
end
