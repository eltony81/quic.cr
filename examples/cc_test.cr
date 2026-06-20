require "../src/quic"
require "log"

Log.setup_from_env(default_level: :info)

puts "🚀 Starting Congestion Control Simulation..."
rec = QUIC::Recovery.new

# Simulate sending 20 packets (each 1000 bytes)
20.times do |i|
  rec.on_packet_sent(i.to_u64, 1000)
end

puts "1. Sent 20 packets. Window size: #{rec.congestion_window}, In Flight: #{rec.bytes_in_flight}"

# Simulate ACK for first 10 packets (Time moves forward)
10.times do |i|
  ack = QUIC::AckFrame.new(i.to_u64, 0_u64, 0_u64)
  rec.on_ack_received(ack, Time.local + 10.milliseconds)
end

puts "2. Acked 10 packets. Window size: #{rec.congestion_window}, In Flight: #{rec.bytes_in_flight}"

# Simulate LOSS for remaining 10 packets (Time moves forward)
# To trigger detect_lost_packets, we advance time beyond loss_delay
now = Time.local + 2.seconds
lost = rec.detect_lost_packets(19_u64, now)

puts "3. Detected #{lost.size} lost packets. (Window is punished automatically inside the detection)"
puts "4. After Loss Event -> Window size: #{rec.congestion_window}, In Flight: #{rec.bytes_in_flight}"
