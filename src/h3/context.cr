module H3
  # Ties together an H3::Request and an H3::Response for a single HTTP/3
  # request-response cycle, providing convenient accessors and shorthands.
  class Context
    getter request  : H3::Request
    getter response : H3::Response

    # Set by handle_request when the actor model is in use; nil in bare unit tests.
    property h3_conn           : H3::Connection? = nil
    property request_stream_id : UInt64?         = nil

    def initialize(@request, @response = H3::Response.new)
    end

    # Shorthand: context.text("hello")
    delegate text,           to: @response
    delegate json,           to: @response
    delegate html,           to: @response
    delegate redirect,       to: @response
    delegate not_found,      to: @response
    delegate internal_error, to: @response
    delegate set_header,     to: @response

    # Shorthand: context.params["id"]
    def params : Hash(String, String)
      @request.query_params
    end

    # Shorthand: context.body_string
    def body_string : String
      @request.body_string
    end

    # Initiates an HTTP/3 server push (RFC 9114 §4.6) for the given path and body.
    # A PUSH_PROMISE is sent on the current request stream, followed by a push
    # response on a new server-initiated unidirectional stream.
    # No-op if h3_conn or request_stream_id are not available (e.g. in unit tests).
    def push_resource(
      path    : String,
      body    : Bytes,
      headers : Hash(String, String) = {} of String => String
    )
      conn = @h3_conn
      sid  = @request_stream_id
      return unless conn && sid

      push_req_headers = {
        ":method"    => "GET",
        ":path"      => path,
        ":scheme"    => "https",
        ":authority" => @request.headers[":authority"]? || "localhost",
      }
      push_resp_headers = {":status" => "200"}.merge(headers)
      conn.server_push(sid, push_req_headers, push_resp_headers, body)
    rescue e
      Log.debug { "server_push failed: #{e.message}" }
    end

    def push_resource(path : String, body : String, headers : Hash(String, String) = {} of String => String)
      push_resource(path, body.to_slice, headers)
    end
  end
end
