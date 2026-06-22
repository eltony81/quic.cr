require "./spec_helper"

# Helper: build a Context from method + path + optional body
private def make_ctx(method : String, path : String, body : Bytes = Bytes.empty) : H3::Context
  req = H3::Request.new({":method" => method, ":path" => path}, body)
  H3::Context.new(req)
end

describe H3::Router do
  # ── Method dispatch ──────────────────────────────────────────────────────────

  it "dispatches GET" do
    router = H3::Router.new
    called = false
    router.get("/") { |ctx| called = true; ctx.text "ok" }
    router.dispatch(make_ctx("GET", "/")).should be_true
    called.should be_true
  end

  it "dispatches POST" do
    router = H3::Router.new
    router.post("/submit") { |ctx| ctx.text "posted" }
    ctx = make_ctx("POST", "/submit")
    router.dispatch(ctx).should be_true
    ctx.response.status.should eq(200)
  end

  it "dispatches PUT" do
    router = H3::Router.new
    router.put("/item") { |ctx| ctx.text "put" }
    router.dispatch(make_ctx("PUT", "/item")).should be_true
  end

  it "dispatches DELETE" do
    router = H3::Router.new
    router.delete("/item") { |ctx| ctx.text "gone" }
    router.dispatch(make_ctx("DELETE", "/item")).should be_true
  end

  it "dispatches PATCH" do
    router = H3::Router.new
    router.patch("/item") { |ctx| ctx.text "patched" }
    router.dispatch(make_ctx("PATCH", "/item")).should be_true
  end

  it "dispatches OPTIONS" do
    router = H3::Router.new
    router.options("/item") { |ctx| ctx.text "options" }
    router.dispatch(make_ctx("OPTIONS", "/item")).should be_true
  end

  it "dispatches HEAD" do
    router = H3::Router.new
    router.head("/") { |ctx| ctx.text "" }
    router.dispatch(make_ctx("HEAD", "/")).should be_true
  end

  # ── No match ─────────────────────────────────────────────────────────────────

  it "returns false when no route matches the path" do
    router = H3::Router.new
    router.get("/found") { |ctx| ctx.text "ok" }
    router.dispatch(make_ctx("GET", "/missing")).should be_false
  end

  it "returns false on method mismatch" do
    router = H3::Router.new
    router.get("/item") { |ctx| ctx.text "ok" }
    router.dispatch(make_ctx("POST", "/item")).should be_false
  end

  it "does not match when segment count differs" do
    router = H3::Router.new
    router.get("/a/b") { |ctx| ctx.text "ok" }
    router.dispatch(make_ctx("GET", "/a")).should be_false
    router.dispatch(make_ctx("GET", "/a/b/c")).should be_false
  end

  # ── Named parameters ─────────────────────────────────────────────────────────

  it "captures a single named param" do
    router = H3::Router.new
    captured = ""
    router.get("/users/:id") { |ctx| captured = ctx.request.path_params["id"] }
    router.dispatch(make_ctx("GET", "/users/42")).should be_true
    captured.should eq("42")
  end

  it "captures multiple named params" do
    router = H3::Router.new
    captured = {} of String => String
    router.get("/users/:uid/posts/:pid") { |ctx| captured = ctx.request.path_params }
    router.dispatch(make_ctx("GET", "/users/7/posts/99")).should be_true
    captured["uid"].should eq("7")
    captured["pid"].should eq("99")
  end

  it "matches static segments before param segments when both exist" do
    router = H3::Router.new
    hit = ""
    router.get("/users/me") { |ctx| hit = "static" }
    router.get("/users/:id") { |ctx| hit = "param" }
    router.dispatch(make_ctx("GET", "/users/me"))
    hit.should eq("static")
  end

  # ── Middleware ───────────────────────────────────────────────────────────────

  it "runs single middleware before the handler" do
    router = H3::Router.new
    order = [] of String
    router.use { |ctx, nxt| order << "mw"; nxt.call(ctx) }
    router.get("/") { |ctx| order << "handler" }
    router.dispatch(make_ctx("GET", "/"))
    order.should eq(["mw", "handler"])
  end

  it "runs multiple middlewares in insertion order" do
    router = H3::Router.new
    order = [] of String
    router.use { |ctx, nxt| order << "first"; nxt.call(ctx) }
    router.use { |ctx, nxt| order << "second"; nxt.call(ctx) }
    router.get("/") { |ctx| order << "handler" }
    router.dispatch(make_ctx("GET", "/"))
    order.should eq(["first", "second", "handler"])
  end

  it "allows middleware to short-circuit the chain without calling next" do
    router = H3::Router.new
    handler_called = false
    router.use { |ctx, _nxt| ctx.response.status = 401 }
    router.get("/") { |ctx| handler_called = true }
    router.dispatch(make_ctx("GET", "/"))
    handler_called.should be_false
  end

  it "middleware can mutate context before the handler" do
    router = H3::Router.new
    router.use { |ctx, nxt| ctx.response.set_header("x-mw", "1"); nxt.call(ctx) }
    router.get("/") { |ctx| ctx.text "ok" }
    ctx = make_ctx("GET", "/")
    router.dispatch(ctx)
    ctx.response.to_h3_headers["x-mw"].should eq("1")
  end

  it "middleware can read path params set by the router" do
    router = H3::Router.new
    captured_from_mw = ""
    router.use { |ctx, nxt| nxt.call(ctx); captured_from_mw = ctx.request.path_params["id"]? || "" }
    router.get("/items/:id") { |_ctx| }
    router.dispatch(make_ctx("GET", "/items/99"))
    captured_from_mw.should eq("99")
  end

  # ── H3::Server integration ───────────────────────────────────────────────────

  it "H3::Server routes GET via router and returns text body" do
    router = H3::Router.new
    router.get("/ping") { |ctx| ctx.text "pong" }
    server = H3::Server.new(router)

    quic_conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
    h3_conn   = H3::Connection.new(quic_conn)
    io        = MockSocket.new(encode_request("GET", "/ping"))
    server.handle_request(h3_conn, io)

    io.write_io.rewind
    frame = H3::Frame.decode(io.write_io)
    frame.should be_a(H3::HeadersFrame)
    frame.as(H3::HeadersFrame).headers[":status"].should eq("200")

    body_frame = H3::Frame.decode(io.write_io)
    body_frame.should be_a(H3::DataFrame)
    String.new(body_frame.as(H3::DataFrame).data).should eq("pong")
  end

  it "H3::Server returns 404 for unregistered path" do
    router = H3::Router.new
    router.get("/exists") { |ctx| ctx.text "ok" }
    server = H3::Server.new(router)

    quic_conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
    h3_conn   = H3::Connection.new(quic_conn)
    io        = MockSocket.new(encode_request("GET", "/nope"))
    server.handle_request(h3_conn, io)

    io.write_io.rewind
    frame = H3::Frame.decode(io.write_io)
    frame.should be_a(H3::HeadersFrame)
    frame.as(H3::HeadersFrame).headers[":status"].should eq("404")
  end

  it "H3::Server echoes POST body via named param route" do
    router = H3::Router.new
    router.post("/echo") { |ctx| ctx.text ctx.body_string }
    server = H3::Server.new(router)

    quic_conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
    h3_conn   = H3::Connection.new(quic_conn)
    body      = "hello body".to_slice
    io        = MockSocket.new(encode_request("POST", "/echo", body))
    server.handle_request(h3_conn, io)

    io.write_io.rewind
    H3::Frame.decode(io.write_io)  # skip headers
    data_frame = H3::Frame.decode(io.write_io)
    data_frame.should be_a(H3::DataFrame)
    String.new(data_frame.as(H3::DataFrame).data).should eq("hello body")
  end

  it "H3::Server delivers path param to handler" do
    router = H3::Router.new
    router.get("/users/:id") { |ctx| ctx.json %({"id":"#{ctx.request.path_params["id"]}"}) }
    server = H3::Server.new(router)

    quic_conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
    h3_conn   = H3::Connection.new(quic_conn)
    io        = MockSocket.new(encode_request("GET", "/users/77"))
    server.handle_request(h3_conn, io)

    io.write_io.rewind
    H3::Frame.decode(io.write_io)  # headers
    data_frame = H3::Frame.decode(io.write_io)
    String.new(data_frame.as(H3::DataFrame).data).should eq(%({"id":"77"}))
  end
end

describe H3::Request do
  it "parses :method pseudo-header" do
    req = H3::Request.new({":method" => "POST", ":path" => "/"}, Bytes.empty)
    req.method.should eq("POST")
  end

  it "defaults method to GET when :method is absent" do
    req = H3::Request.new({":path" => "/"}, Bytes.empty)
    req.method.should eq("GET")
  end

  it "parses path without query string" do
    req = H3::Request.new({":method" => "GET", ":path" => "/foo/bar"}, Bytes.empty)
    req.path.should eq("/foo/bar")
    req.query_string.should eq("")
  end

  it "splits path and query string at '?'" do
    req = H3::Request.new({":method" => "GET", ":path" => "/search?q=crystal&page=2"}, Bytes.empty)
    req.path.should eq("/search")
    req.query_string.should eq("q=crystal&page=2")
  end

  it "parses query_params as a Hash" do
    req = H3::Request.new({":method" => "GET", ":path" => "/items?sort=asc&limit=10"}, Bytes.empty)
    params = req.query_params
    params["sort"].should eq("asc")
    params["limit"].should eq("10")
  end

  it "returns empty query_params when no query string" do
    req = H3::Request.new({":method" => "GET", ":path" => "/"}, Bytes.empty)
    req.query_params.should be_empty
  end

  it "strips pseudo-headers from .headers" do
    req = H3::Request.new(
      {":method" => "GET", ":path" => "/", "content-type" => "application/json"},
      Bytes.empty
    )
    req.headers.keys.should_not contain(":method")
    req.headers.keys.should_not contain(":path")
    req.headers["content-type"].should eq("application/json")
  end

  it "exposes body as bytes and as string" do
    body = "hello".to_slice
    req  = H3::Request.new({":method" => "POST", ":path" => "/"}, body)
    req.body.should eq(body)
    req.body_string.should eq("hello")
  end

  it "json? is true when content-type contains application/json" do
    req = H3::Request.new(
      {":method" => "POST", ":path" => "/", "content-type" => "application/json"},
      Bytes.empty
    )
    req.json?.should be_true
  end

  it "json? is false for non-JSON content-type" do
    req = H3::Request.new(
      {":method" => "POST", ":path" => "/", "content-type" => "text/plain"},
      Bytes.empty
    )
    req.json?.should be_false
  end

  it "content_type returns the content-type header" do
    req = H3::Request.new(
      {":method" => "POST", ":path" => "/", "content-type" => "application/octet-stream"},
      Bytes.empty
    )
    req.content_type.should eq("application/octet-stream")
  end

  it "content_type returns empty string when absent" do
    req = H3::Request.new({":method" => "GET", ":path" => "/"}, Bytes.empty)
    req.content_type.should eq("")
  end
end

describe H3::Response do
  it "defaults to status 200 and no body" do
    r = H3::Response.new
    r.status.should eq(200)
    r.body_bytes.should be_empty
  end

  it "#text sets body, content-type, and status" do
    r = H3::Response.new
    r.text("hello", 201)
    r.status.should eq(201)
    r.to_h3_headers["content-type"].should eq("text/plain; charset=utf-8")
    String.new(r.body_bytes).should eq("hello")
  end

  it "#json sets body and application/json content-type" do
    r = H3::Response.new
    r.json(%[{"ok":true}])
    r.to_h3_headers["content-type"].should eq("application/json; charset=utf-8")
    String.new(r.body_bytes).should eq(%[{"ok":true}])
  end

  it "#html sets body and text/html content-type" do
    r = H3::Response.new
    r.html("<h1>hi</h1>")
    r.to_h3_headers["content-type"].should eq("text/html; charset=utf-8")
    String.new(r.body_bytes).should eq("<h1>hi</h1>")
  end

  it "#redirect sets location header and 302 by default" do
    r = H3::Response.new
    r.redirect("/new-path")
    r.status.should eq(302)
    r.to_h3_headers["location"].should eq("/new-path")
  end

  it "#redirect accepts a custom status code" do
    r = H3::Response.new
    r.redirect("/perm", 301)
    r.status.should eq(301)
    r.to_h3_headers["location"].should eq("/perm")
  end

  it "#not_found sets 404 and the supplied message" do
    r = H3::Response.new
    r.not_found("gone")
    r.status.should eq(404)
    String.new(r.body_bytes).should eq("gone")
  end

  it "#not_found uses default message when none supplied" do
    r = H3::Response.new
    r.not_found
    r.status.should eq(404)
    String.new(r.body_bytes).should eq("Not Found")
  end

  it "#internal_error sets 500" do
    r = H3::Response.new
    r.internal_error
    r.status.should eq(500)
  end

  it "#set_header stores header in lowercase" do
    r = H3::Response.new
    r.set_header("X-Custom", "val")
    r.to_h3_headers["x-custom"].should eq("val")
  end

  it "to_h3_headers includes :status" do
    r = H3::Response.new
    r.text("ok")
    r.to_h3_headers[":status"].should eq("200")
  end

  it "to_h3_headers includes content-length for non-empty body" do
    r = H3::Response.new
    r.text("abc")
    r.to_h3_headers["content-length"].should eq("3")
  end

  it "to_h3_headers omits content-length for empty body" do
    r = H3::Response.new
    r.to_h3_headers.has_key?("content-length").should be_false
  end

  it "#write appends raw bytes to body" do
    r = H3::Response.new
    r.write("hello".to_slice)
    r.write(" world".to_slice)
    String.new(r.body_bytes).should eq("hello world")
  end

  it "#print appends a string to body" do
    r = H3::Response.new
    r.print("hi")
    String.new(r.body_bytes).should eq("hi")
  end
end

describe H3::Context do
  it "delegates text to response" do
    ctx = make_ctx("GET", "/")
    ctx.text("hi", 202)
    ctx.response.status.should eq(202)
    String.new(ctx.response.body_bytes).should eq("hi")
  end

  it "delegates json to response" do
    ctx = make_ctx("GET", "/")
    ctx.json(%[{"x":1}])
    ctx.response.to_h3_headers["content-type"].should contain("application/json")
  end

  it "delegates html to response" do
    ctx = make_ctx("GET", "/")
    ctx.html("<p>hi</p>")
    ctx.response.to_h3_headers["content-type"].should contain("text/html")
  end

  it "delegates redirect to response" do
    ctx = make_ctx("GET", "/")
    ctx.redirect("/elsewhere")
    ctx.response.status.should eq(302)
    ctx.response.to_h3_headers["location"].should eq("/elsewhere")
  end

  it "delegates not_found to response" do
    ctx = make_ctx("GET", "/")
    ctx.not_found
    ctx.response.status.should eq(404)
  end

  it "delegates internal_error to response" do
    ctx = make_ctx("GET", "/")
    ctx.internal_error
    ctx.response.status.should eq(500)
  end

  it "delegates set_header to response" do
    ctx = make_ctx("GET", "/")
    ctx.set_header("x-trace", "abc")
    ctx.response.to_h3_headers["x-trace"].should eq("abc")
  end

  it "#params returns request query params" do
    ctx = make_ctx("GET", "/search?q=test&n=3")
    ctx.params["q"].should eq("test")
    ctx.params["n"].should eq("3")
  end

  it "#body_string returns request body decoded as string" do
    req = H3::Request.new({":method" => "POST", ":path" => "/"}, "payload".to_slice)
    ctx = H3::Context.new(req)
    ctx.body_string.should eq("payload")
  end
end

# ── Helpers ───────────────────────────────────────────────────────────────────

private def encode_request(method : String, path : String, body : Bytes = Bytes.empty) : Bytes
  h3_conn = H3::Connection.new(QUIC::Connection.new(QUIC::Config.new, is_server: false))
  io = IO::Memory.new
  h3_conn.write_frame(io, H3::HeadersFrame.new({":method" => method, ":scheme" => "https",
    ":authority" => "localhost", ":path" => path}))
  h3_conn.write_frame(io, H3::DataFrame.new(body)) unless body.empty?
  io.to_slice
end
