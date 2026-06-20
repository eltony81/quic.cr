module H3
  # Ties together an H3::Request and an H3::Response for a single HTTP/3
  # request-response cycle, providing convenient accessors and shorthands.
  class Context
    getter request  : H3::Request
    getter response : H3::Response

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
  end
end
