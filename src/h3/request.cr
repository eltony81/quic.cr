module H3
  # Wraps an incoming HTTP/3 request, exposing method, path, headers,
  # query parameters, and body in a Crystal-idiomatic interface.
  class Request
    getter method : String
    getter path : String
    getter query_string : String
    getter headers : Hash(String, String)
    getter body : Bytes
    getter remote_address : String

    def initialize(
      raw_headers : Hash(String, String),
      @body : Bytes,
      @remote_address : String = ""
    )
      @method         = raw_headers[":method"]? || "GET"
      full_path       = raw_headers[":path"]? || "/"
      if (idx = full_path.index('?'))
        @path         = full_path[0, idx]
        @query_string = full_path[idx + 1..]
      else
        @path         = full_path
        @query_string = ""
      end
      # Copy only non-pseudo headers
      @headers = raw_headers.reject { |k, _| k.starts_with?(":") }
    end

    # Returns the :authority pseudo-header value.
    def authority : String
      @headers[":authority"]? || ""
    end

    # Parses the query string into a Hash.
    def query_params : Hash(String, String)
      result = {} of String => String
      @query_string.split("&").each do |pair|
        k, _, v = pair.partition("=")
        result[URI.decode(k)] = URI.decode(v) unless k.empty?
      end
      result
    end

    # Returns the body decoded as UTF-8.
    def body_string : String
      String.new(@body)
    end

    # Returns the content-type header value.
    def content_type : String
      @headers["content-type"]? || ""
    end

    # True when Content-Type contains application/json.
    def json? : Bool
      content_type.includes?("application/json")
    end
  end
end
