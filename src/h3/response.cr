module H3
  # Builds and represents an HTTP/3 response. Offers fluent helpers akin to
  # Crystal's standard `HTTP::Server::Response`.
  struct Response
    STATUS_TEXTS = {
      200 => "OK",
      201 => "Created",
      204 => "No Content",
      301 => "Moved Permanently",
      302 => "Found",
      400 => "Bad Request",
      401 => "Unauthorized",
      403 => "Forbidden",
      404 => "Not Found",
      405 => "Method Not Allowed",
      415 => "Unsupported Media Type",
      422 => "Unprocessable Entity",
      429 => "Too Many Requests",
      500 => "Internal Server Error",
      503 => "Service Unavailable",
    }

    property status : Int32 = 200
    getter headers : Hash(String, String)
    @body : IO::Memory = IO::Memory.new

    def initialize
      @headers = {
        "server" => "quic.cr/h3",
      }
    end

    # ------------------------------------------------------------------ Body

    # Write raw bytes to the response body.
    def write(data : Bytes) : Nil
      @body.write(data)
    end

    # Write a string to the response body.
    def print(str : String) : Nil
      @body.print(str)
    end

    # ------------------------------------------------------------------ Helpers

    # Respond with plain text.
    def text(body : String, status : Int32 = 200)
      self.status = status
      @headers["content-type"] = "text/plain; charset=utf-8"
      @body = IO::Memory.new(body.to_slice)
    end

    # Respond with JSON (no serialisation — caller provides the JSON string).
    def json(body : String, status : Int32 = 200)
      self.status = status
      @headers["content-type"] = "application/json; charset=utf-8"
      @body = IO::Memory.new(body.to_slice)
    end

    # Respond with HTML.
    def html(body : String, status : Int32 = 200)
      self.status = status
      @headers["content-type"] = "text/html; charset=utf-8"
      @body = IO::Memory.new(body.to_slice)
    end

    # Emit a redirect.
    def redirect(location : String, status : Int32 = 302)
      self.status = status
      @headers["location"] = location
    end

    # Shortcut for 404 Not Found.
    def not_found(message : String = "Not Found")
      text(message, 404)
    end

    # Shortcut for 500 Internal Server Error.
    def internal_error(message : String = "Internal Server Error")
      text(message, 500)
    end

    # Set an arbitrary header.
    def set_header(name : String, value : String)
      @headers[name.downcase] = value
    end

    # ------------------------------------------------------------------ Internal

    # Returns the fully assembled (pseudo-)header hash for QPACK encoding.
    def to_h3_headers : Hash(String, String)
      h = {":status" => status.to_s}
      @headers.each { |k, v| h[k] = v }
      size = @body.size
      h["content-length"] = size.to_s if size > 0
      h
    end

    # Returns the assembled body bytes.
    def body_bytes : Bytes
      @body.to_slice
    end
  end
end
