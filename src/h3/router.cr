module H3
  # Type alias for a route handler block: receives a Context and returns nothing —
  # the handler populates ctx.response directly.
  alias Handler = Proc(Context, Nil)

  # Type alias for middleware: wraps a handler, calls next when done.
  alias Middleware = Proc(Context, Handler, Nil)

  # A trie-based HTTP/3 router with middleware support.
  #
  # Usage:
  #
  #   router = H3::Router.new
  #
  #   # Middleware (runs before every handler)
  #   router.use do |ctx, next_handler|
  #     Log.info { "#{ctx.request.method} #{ctx.request.path}" }
  #     next_handler.call(ctx)
  #   end
  #
  #   router.get "/" do |ctx|
  #     ctx.text "Hello from quic.cr!"
  #   end
  #
  #   router.post "/echo" do |ctx|
  #     ctx.json %({"echo": #{ctx.body_string.inspect}})
  #   end
  #
  #   router.get "/users/:id" do |ctx|
  #     id = ctx.request.path_params["id"]
  #     ctx.json %({"id": "#{id}"})
  #   end
  class Router
    # A single registered route.
    private record Route,
      method : String,
      pattern : String,
      segments : Array(String),
      handler : Handler

    @routes : Array(Route) = [] of Route
    @middleware : Array(Middleware) = [] of Middleware

    # ------------------------------------------------------------------ Middleware

    # Register a middleware block. Middlewares are called in insertion order.
    def use(&block : Middleware)
      @middleware << block
    end

    # ------------------------------------------------------------------ Route Registration

    {% for verb in %w[get post put patch delete options head] %}
      def {{verb.id}}(pattern : String, &block : Handler)
        register({{verb.upcase}}, pattern, block)
      end
    {% end %}

    # ------------------------------------------------------------------ Internal

    private def register(method : String, pattern : String, handler : Handler)
      segments = pattern.split("/").reject(&.empty?)
      @routes << Route.new(
        method:   method,
        pattern:  pattern,
        segments: segments,
        handler:  handler
      )
    end

    # Dispatches a Context to the first matching route, running the middleware
    # chain around it. Returns true if a route matched, false otherwise.
    def dispatch(ctx : Context) : Bool
      req_method   = ctx.request.method.upcase
      req_segments = ctx.request.path.split("/").reject(&.empty?)

      @routes.each do |route|
        next unless route.method == req_method || route.method == "ANY"
        path_params = match_route(route.segments, req_segments)
        next if path_params.nil?

        # Attach path params to request headers for handler access
        path_params.each { |k, v| ctx.request.headers["_param_#{k}"] = v }

        final_handler = build_chain(@middleware, route.handler)
        final_handler.call(ctx)
        return true
      end
      false
    end

    # Build a composed middleware chain around the inner handler.
    private def build_chain(middlewares : Array(Middleware), inner : Handler) : Handler
      # Walk middleware in reverse so the first middleware is outermost.
      chain = inner
      middlewares.reverse_each do |mw|
        outer = chain   # capture by value in closure
        chain = Handler.new do |ctx|
          mw.call(ctx, outer)
        end
      end
      chain
    end

    # Returns a hash of path param captures if the route matches, nil otherwise.
    private def match_route(pattern_segs : Array(String), req_segs : Array(String)) : Hash(String, String)?
      return nil unless pattern_segs.size == req_segs.size

      params = {} of String => String
      pattern_segs.each_with_index do |seg, i|
        if seg.starts_with?(":")
          params[seg[1..]] = req_segs[i]
        elsif seg != req_segs[i]
          return nil
        end
      end
      params
    end
  end
end

# Extend H3::Request so handlers can read path params stored by the router.
module H3
  struct Request
    # Returns path parameters captured by the router (e.g. :id -> "42").
    def path_params : Hash(String, String)
      result = {} of String => String
      @headers.each do |k, v|
        result[$1] = v if k =~ /^_param_(.+)$/
      end
      result
    end
  end
end
