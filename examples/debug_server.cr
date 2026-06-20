require "../src/quic"

Log.setup_from_env(default_level: :none)

# Expose streams getter if not already exposed
class QUIC::Connection
  getter streams
  def closed?
    @closed
  end
end

router = H3::Router.new
router.get "/greet" do |ctx|
  name = ctx.params["name"]? || "stranger"
  ctx.json %({"message": "Hello, #{name}!"})
end

server = H3::Server.new(router)

config = QUIC::Config.new
config.cert_file = File.join(__DIR__, "..", "cert.pem")
config.key_file = File.join(__DIR__, "..", "key.pem")
config.initial_max_data = 10_000_000_u64
config.initial_max_stream_data_bidi_local  = 1_000_000_u64
config.initial_max_stream_data_bidi_remote = 1_000_000_u64
config.initial_max_streams_bidi = 128_u64
config.initial_max_streams_uni  = 128_u64
config.initial_max_stream_data_uni = 1_000_000_u64

connections    = {} of String => {QUIC::Connection, H3::Connection}
handled_streams = Set(Tuple(String, UInt64)).new
buf     = Bytes.new(65536)
out_buf = Bytes.new(65536)

udp = UDPSocket.new
udp.bind("127.0.0.1", 4433)
STDERR.puts "🚀 Listening on udp://127.0.0.1:4433"

loop do
  size, client_addr = udp.receive(buf)
  data = buf[0, size]

  io = IO::Memory.new(data)
  first = io.read_byte || 0_u8
  is_long = (first & 0x80) != 0
  conn_key = if is_long
    io.skip(4)
    len = io.read_byte || 0_u8
    dcid = Bytes.new(len)
    io.read_fully(dcid)
    dcid.hexstring
  else
    dcid = Bytes.new(8)
    io.read_fully(dcid)
    dcid.hexstring
  end

  conn_tuple = connections[conn_key]?
  if conn_tuple.nil?
    STDERR.puts "New connection #{conn_key}"
    quic_conn = QUIC::Connection.new(config, is_server: true)
    h3_conn   = H3::Connection.new(quic_conn)
    conn_tuple = {quic_conn, h3_conn}
    connections[conn_key] = conn_tuple

    ctrl = h3_conn.open_uni_stream(0_u64)
    sf   = H3::SettingsFrame.new
    sf.settings = {0x01_u64 => 0_u64, 0x07_u64 => 100_u64, 0x06_u64 => 100_u64}
    h3_conn.write_frame(ctrl, sf)
  end

  quic_conn, h3_conn = conn_tuple
  quic_conn.recv(data)
  STDERR.puts "After recv: closed=#{quic_conn.closed?} streams=#{quic_conn.streams.keys}"

  if scid = quic_conn.scid
    connections[scid.hexstring] = conn_tuple
  end

  quic_conn.streams.each do |stream_id, _stream|
    next unless stream_id % 4 == 0
    stream_key = {conn_key, stream_id}
    next if handled_streams.includes?(stream_key)
    handled_streams << stream_key

    sock = QUIC::StreamSocket.new(quic_conn, stream_id)
    begin
      server.handle_request(h3_conn, sock)
      STDERR.puts "Handled stream #{stream_id}, closed after=#{quic_conn.closed?}"
    rescue e
      STDERR.puts "Error: #{e.class} #{e.message}"
    end
  end

  sent_pkts = 0
  while (n = quic_conn.send(out_buf)) > 0
    udp.send(out_buf[0, n], client_addr)
    sent_pkts += 1
  end
  STDERR.puts "Sent #{sent_pkts} packets"
end
