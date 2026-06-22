require "../src/quic"

config = QUIC::Config.new
config.cert_file = "cert.pem"
config.key_file  = "key.pem"

t0 = Time.instant
conn0 = QUIC::Connection.new(config, is_server: true)
puts "First Connection.new (cert load): #{(Time.instant - t0).total_milliseconds.round(2)}ms"

times = [] of Float64
8.times do
  t = Time.instant
  conn = QUIC::Connection.new(config, is_server: true)
  times << (Time.instant - t).total_milliseconds
end
avg = times.sum / times.size
puts "8x cached Connection.new: avg=#{avg.round(2)}ms  total=#{times.sum.round(2)}ms"
puts "Individual: #{times.map{|t| "#{t.round(1)}ms"}.join(", ")}"
