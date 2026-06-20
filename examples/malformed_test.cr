require "socket"

puts "🚀 Starting Malformed QUIC Client (VarInt Crash)..."
client = UDPSocket.new
client.connect("127.0.0.1", 4433)

# 0xC0 = Initial
# 00 00 00 01 = Version 1
# 00 = DCID Len
# 00 = SCID Len
# 00 = Token Len (0)
# FF FF FF FF FF FF FF FF = Length VarInt (indicante che servono altri 8 byte ma tronchiamo qui)
bad_packet = Bytes[0xC0_u8, 0_u8, 0_u8, 0_u8, 1_u8, 0_u8, 0_u8, 0_u8, 0xFF_u8, 0xFF_u8, 0xFF_u8, 0xFF_u8, 0xFF_u8]
client.send(bad_packet)

puts "💣 Sent corrupted VarInt QUIC packet (size: #{bad_packet.size})"
