require "../src/quic/crypto"

# RFC 9001 Appendix A.1 values
dcid = "8394c8f03e515708".hexbytes

initial_secret = QUIC::Crypto.hkdf_extract(QUIC::Crypto::INITIAL_SALT_V1, dcid)
puts "Derived initial secret:  #{initial_secret.hexstring}"
puts "Expected initial secret: 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"

client_secret = QUIC::Crypto.hkdf_expand_label(initial_secret, "client in", Bytes.empty, 32)
puts "Derived client secret:   #{client_secret.hexstring}"
puts "Expected client secret:  c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"

# Derive keys
client_key = QUIC::Crypto.hkdf_expand_label(client_secret, "quic key", Bytes.empty, 16)
client_iv  = QUIC::Crypto.hkdf_expand_label(client_secret, "quic iv", Bytes.empty, 12)
client_hp  = QUIC::Crypto.hkdf_expand_label(client_secret, "quic hp", Bytes.empty, 16)

puts "Derived client key:      #{client_key.hexstring}"
puts "Expected client key:     1f8f397a04c087f2fb8f6688541c7e2c"

puts "Derived client iv:       #{client_iv.hexstring}"
puts "Expected client iv:      d491db0a293b3b97dc6a1027"

puts "Derived client hp:       #{client_hp.hexstring}"
puts "Expected client hp:      25a282b9e82f06f21f1274182f773301"
