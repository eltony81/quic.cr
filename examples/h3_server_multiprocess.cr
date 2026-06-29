require "../src/quic"

# Multi-process HTTP/3 server using SO_REUSEPORT.
#
# H3::Server already sets SO_REUSEPORT on its UDP socket, so N processes
# can all bind to the same port simultaneously. The Linux kernel distributes
# incoming QUIC connections between them using a hash of the 4-tuple
# (src_ip, src_port, dst_ip, dst_port) — no packet duplication, no shared
# state between workers, no mutexes.
#
# This scales linearly with CPU cores for multi-connection workloads,
# unlike -Dpreview_mt which adds mutex overhead on every channel operation
# and provides little benefit for single-connection-per-worker patterns.
#
# Usage:
#   # Single worker (development):
#   crystal run examples/h3_server_multiprocess.cr
#
#   # Multi-worker (production — compile first for real numbers):
#   crystal build examples/h3_server_multiprocess.cr -o /tmp/h3_multi --release
#   WORKERS=4 /tmp/h3_multi
#   WORKERS=$(nproc) PORT=4433 /tmp/h3_multi
#
# Test — each response includes the worker pid to show kernel distribution:
#   for i in $(seq 1 12); do
#     curl -s --http3 https://127.0.0.1:4433/ --insecure
#   done
#
# Graceful shutdown:
#   kill -TERM <parent_pid>

WORKERS = (ENV["WORKERS"]? || "1").to_i.clamp(1, 256)
PORT    = (ENV["PORT"]?    || "4433").to_i
CERT    = File.join(__DIR__, "..", "cert.pem")
KEY     = File.join(__DIR__, "..", "key.pem")

Log.setup_from_env(default_level: :info)

def build_router : H3::Router
  router = H3::Router.new

  router.use do |ctx, nxt|
    t0 = Time.instant
    nxt.call(ctx)
    ms = (Time.instant - t0).total_milliseconds
    Log.info { "[pid #{Process.pid}] #{ctx.request.method} #{ctx.request.path} → #{ctx.response.status} (#{ms.round(1)}ms)" }
  end

  router.get "/" do |ctx|
    ctx.json %({"server":"quic.cr","pid":#{Process.pid},"workers":#{WORKERS}})
  end

  router.get "/ping" { |ctx| ctx.text "pong" }

  router.get "/greet" do |ctx|
    name = ctx.params["name"]? || "stranger"
    ctx.json %({"message":"Hello, #{name}!","pid":#{Process.pid}})
  end

  router.get "/users/:id" do |ctx|
    id = ctx.request.path_params["id"]
    ctx.json %({"id":"#{id}","pid":#{Process.pid}})
  end

  router.post "/echo" { |ctx| ctx.text ctx.body_string }

  router
end

def run_worker
  server = H3::Server.new(build_router)
  Signal::INT.trap  { server.shutdown; exit 0 }
  Signal::TERM.trap { server.shutdown; exit 0 }
  Log.info { "Worker pid=#{Process.pid} listening on :#{PORT}" }
  server.listen(host: "0.0.0.0", port: PORT, cert: CERT, key: KEY)
end

# ── Worker entry point ────────────────────────────────────────────────────────
# When the parent spawns children it sets _H3_WORKER=1. Children skip
# supervisor logic and go straight to serving.

if ENV["_H3_WORKER"]? == "1"
  run_worker
  exit 0
end

# ── Single-worker shortcut ────────────────────────────────────────────────────

if WORKERS == 1
  run_worker
  exit 0
end

# ── Multi-worker supervisor ───────────────────────────────────────────────────
# Spawn N copies of this binary with _H3_WORKER=1.
# The kernel distributes QUIC connections via SO_REUSEPORT.

exe = Process.executable_path
unless exe
  STDERR.puts "Cannot determine executable path. Compile first:\n" \
              "  crystal build examples/h3_server_multiprocess.cr -o /tmp/h3_multi --release"
  exit 1
end

Log.info { "Starting #{WORKERS} workers on :#{PORT} (SO_REUSEPORT)" }

# Inherit the current env and add the worker flag.
worker_env = ENV.to_h.merge({
  "_H3_WORKER" => "1",
  "WORKERS"    => WORKERS.to_s,
  "PORT"       => PORT.to_s,
})

children = Array(Process).new(WORKERS)

spawn_worker = ->() : Process {
  Process.new(
    command: exe,
    env: worker_env,
    input: Process::Redirect::Close,
    output: Process::Redirect::Inherit,
    error: Process::Redirect::Inherit,
  )
}

WORKERS.times { children << spawn_worker.call }
Log.info { "Workers: #{children.map(&.pid).join(", ")}" }

# Forward shutdown signals to all children.
shutdown = ->(_s : Signal) {
  Log.info { "Shutting down #{children.size} workers…" }
  children.each { |c| c.signal(Signal::TERM) rescue nil }
  children.each { |c| c.wait rescue nil }
  Log.info { "All workers stopped." }
  exit 0
}
Signal::INT.trap  { shutdown.call(Signal::INT) }
Signal::TERM.trap { shutdown.call(Signal::TERM) }

# Supervisor loop: reap exited workers, restart crashed ones.
loop do
  children.select! do |child|
    next true if child.exists?  # still running

    status = child.wait
    if status.normal_exit?
      Log.info { "Worker #{child.pid} exited normally." }
      false
    else
      Log.warn { "Worker #{child.pid} crashed (exit #{status.exit_code}), restarting…" }
      children << spawn_worker.call
      Log.info { "  Restarted as pid #{children.last.pid}" }
      false
    end
  end

  break if children.empty?
  sleep 500.milliseconds
end
