require "http/server"
require "openssl"

# Crystal standard HTTP/1.1+TLS benchmark server.
# Routes mirror crystal_server.cr (quic.cr) so the 3-way benchmark
# compares protocol overhead on identical application logic.
Log.setup(:warn)

server = HTTP::Server.new do |ctx|
  req = ctx.request
  res = ctx.response

  method = req.method
  path   = req.path

  case {method, path}
  when {"GET", "/"}
    res.content_type = "text/html"
    res.print "<!DOCTYPE html><html><body><h1>Crystal HTTP/1.1 Server</h1><p>stdlib benchmark</p></body></html>"

  when {"GET", "/greet"}
    name = req.query_params["name"]? || "stranger"
    res.content_type = "application/json"
    res.print %({"message":"Hello, #{name}!","server":"crystal-http"})

  when {"GET", "/healthz"}
    res.content_type = "application/json"
    res.print %({"status":"ok","server":"crystal-http"})

  else
    if method == "GET" && (m = path.match(/^\/users\/([^\/]+)$/))
      id = m[1]
      res.content_type = "application/json"
      res.print %({"user":{"id":"#{id}","status":"active"}})

    elsif method == "POST" && path == "/echo"
      body_str = req.body.try(&.gets_to_end) || ""
      ct = req.headers["content-type"]? || ""
      if ct.includes?("json")
        res.content_type = "application/json"
        res.print %({"echo":#{body_str.inspect},"bytes":#{body_str.bytesize}})
      else
        res.content_type = "text/plain"
        res.print "Echo: #{body_str}"
      end

    else
      res.status_code = 404
      res.print "Not Found"
    end
  end
end

tls = OpenSSL::SSL::Context::Server.new
tls.certificate_chain = File.join(__DIR__, "..", "cert.pem")
tls.private_key        = File.join(__DIR__, "..", "key.pem")

addr = server.bind_tls("127.0.0.1", 4435, tls)
STDOUT.puts "Crystal HTTP/1.1 server listening on https://#{addr}"
STDOUT.flush
server.listen
