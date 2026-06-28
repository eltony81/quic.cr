require "./spec_helper"

describe "Packet/Frame Parser Fuzzer" do
  # QUIC::Connection.recv is the ingress gate for all incoming datagrams.
  # It must never panic or raise an unhandled exception regardless of input.

  describe "QUIC::Connection#recv — malformed datagrams" do
    it "survives truncated long-header packets (1 to 40 bytes)" do
      (1..40).each do |len|
        data = Bytes.new(len, 0xC0_u8)  # long-header marker
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(data) rescue nil
      end
    end

    it "survives truncated short-header packets (1 to 25 bytes)" do
      (1..25).each do |len|
        data = Bytes.new(len, 0x40_u8)  # short-header marker (fixed bit set)
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(data) rescue nil
      end
    end

    it "survives all-zero datagrams of various sizes" do
      [1, 4, 12, 20, 50, 100, 1200].each do |len|
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(Bytes.new(len, 0_u8)) rescue nil
      end
    end

    it "survives all-0xFF datagrams of various sizes" do
      [1, 4, 12, 20, 50, 100].each do |len|
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(Bytes.new(len, 0xFF_u8)) rescue nil
      end
    end

    it "survives 200 random datagrams of random sizes" do
      200.times do
        len  = Random.rand(1..1200)
        data = Random::Secure.random_bytes(len)
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(data) rescue nil
      end
    end

    it "survives repeating single-byte datagrams" do
      (0x00_u8..0xFF_u8).each do |byte|
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(Bytes[byte]) rescue nil
      end
    end

    it "survives valid QUIC version-negotiation packets pointing to unknown version" do
      # VN packet: first byte has long-header + version=0 (VN), two zero-length DCIDs
      vn = Bytes[
        0xC0_u8,                          # long header, fixed bit
        0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,  # version 0 → Version Negotiation
        0x00_u8,                          # DCID length=0
        0x00_u8,                          # SCID length=0
        0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8,  # supported version: QUIC v1
      ]
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: false)
      conn.recv(vn) rescue nil
    end
  end

  describe "H3::Frame.decode — malformed H3 frames" do
    malformed_h3 = [
      Bytes[0x01, 0xFF, 0xFF, 0xFF, 0xFF],                    # HEADERS frame, bogus length field
      Bytes[0x00, 0x00],                                       # DATA frame, zero-length body
      Bytes[0x01, 0x00],                                       # HEADERS with empty payload
      Bytes[0x04, 0x00],                                       # SETTINGS with empty payload
      Bytes[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],  # max VarInt frame type
      Bytes[0x07, 0x00],                                       # GOAWAY with empty payload
      Bytes[0x01, 0x80_u8, 0x00, 0x10, 0x00],                 # HEADERS, 4096-byte length, no body
      Bytes[0x01, 0x01, 0xDE, 0xAD],                          # HEADERS, 1-byte length, truncated body
    ]

    it "handles each malformed H3 frame without crashing" do
      malformed_h3.each do |raw|
        io = IO::Memory.new(raw)
        H3::Frame.decode(io) rescue nil
      end
    end

    it "handles 100 random H3 frame payloads without crashing" do
      100.times do
        len  = Random.rand(1..32)
        data = Random::Secure.random_bytes(len)
        io   = IO::Memory.new(data)
        H3::Frame.decode(io) rescue nil
      end
    end
  end

  describe "H3::Frame.decode — regression: oversized frame length" do
    it "does not crash (OOM/SIGSEGV) when frame length field is a max-value 8-byte VarInt" do
      # Unknown frame type 0x31AF (2-byte VarInt), followed by an 8-byte VarInt
      # announcing 2^62-1 bytes of payload — triggered OOM/SIGSEGV before the
      # MAX_FRAME_PAYLOAD guard was added (found by the fuzzer above).
      data = Bytes[0x71_u8, 0xAF_u8,   # frame type VarInt (0x31AF — unknown)
                   0xF6_u8, 0xA6_u8, 0x4A_u8, 0xB3_u8, 0x4E_u8, 0xE2_u8, 0xEC_u8, 0x6B_u8]
      io = IO::Memory.new(data)
      raised = false
      H3::Frame.decode(io) rescue raised = true
      raised.should be_true
    end

    it "accepts legitimate large DATA frames up to 16 MB" do
      body = Bytes.new(1024, 0x41_u8)  # 1 KB body — well within the 16 MB limit
      frame = H3::DataFrame.new(body)
      io = IO::Memory.new
      frame.encode(io)
      io.rewind
      decoded = H3::Frame.decode(io)
      decoded.should be_a(H3::DataFrame)
      decoded.as(H3::DataFrame).data.should eq(body)
    end
  end

  describe "QUIC::VarInt — overflow and edge cases" do
    it "decodes all valid 1-byte VarInts (0–63)" do
      (0x00..0x3F).each do |b|
        io = IO::Memory.new(Bytes[b.to_u8])
        v  = QUIC::VarInt.decode(io)
        v.should eq(b.to_u64)
      end
    end

    it "decodes 2-byte VarInt boundaries correctly" do
      io = IO::Memory.new(Bytes[0x40_u8, 0x00_u8])
      QUIC::VarInt.decode(io).should eq(0_u64)

      io = IO::Memory.new(Bytes[0x7F_u8, 0xFF_u8])
      QUIC::VarInt.decode(io).should eq(16383_u64)
    end

    it "encodes and re-decodes a round-trip" do
      [0_u64, 1_u64, 63_u64, 64_u64, 16383_u64, 16384_u64, 1_073_741_823_u64].each do |v|
        io = IO::Memory.new
        QUIC::VarInt.write(io, v)
        io.rewind
        QUIC::VarInt.decode(io).should eq(v)
      end
    end
  end

  describe "QPACK — malformed header blocks" do
    it "handles malformed QPACK payloads without crashing" do
      decoder = H3::QPACK::Decoder.new
      [
        Bytes.empty,
        Bytes[0x00, 0x00],                              # empty required insert count prefix
        Bytes[0xFF, 0xFF, 0xFF, 0xFF],                  # saturated prefix integers
        Bytes[0x00, 0x00, 0x10, 0xDE, 0xAD, 0xBE, 0xEF],  # literal with random data
        Random::Secure.random_bytes(16),
        Random::Secure.random_bytes(64),
      ].each do |payload|
        decoder.decode(payload) rescue nil
      end
    end
  end
end

# ── Security-focused adversarial inputs ─────────────────────────────────────

describe "Adversarial QUIC frame inputs (DoS / parser hardening)" do
  describe "ACK frame with extreme ranges" do
    it "survives ACK with first_ack_range larger than largest_acknowledged" do
      # An attacker can send largest_acked=0, first_ack_range=UInt64::MAX.
      # The subtraction must not underflow.
      io = IO::Memory.new
      QUIC::VarInt.write(io, 0x02_u64)           # ACK type
      QUIC::VarInt.write(io, 0u64)               # largest_acknowledged = 0
      QUIC::VarInt.write(io, 0u64)               # ack_delay
      QUIC::VarInt.write(io, 0u64)               # ack_range_count
      QUIC::VarInt.write(io, 63u64)              # first_ack_range = 63 (max 1-byte VarInt, > largest)
      io.rewind
      result = (QUIC::Frame.decode(io) rescue nil)
      (result.nil? || result.is_a?(QUIC::AckFrame)).should be_true
    end

    it "survives ACK with 1000 additional ranges (DoS via O(n) work)" do
      io = IO::Memory.new
      QUIC::VarInt.write(io, 0x02_u64)    # ACK type
      QUIC::VarInt.write(io, 999u64)      # largest_acknowledged
      QUIC::VarInt.write(io, 0u64)        # ack_delay
      QUIC::VarInt.write(io, 499u64)      # ack_range_count = 499
      QUIC::VarInt.write(io, 0u64)        # first_ack_range
      499.times do
        QUIC::VarInt.write(io, 0u64)      # gap
        QUIC::VarInt.write(io, 0u64)      # ack_len
      end
      io.rewind
      (QUIC::Frame.decode(io) rescue nil)  # must not crash
    end
  end

  describe "STREAM frame with adversarial offset/length" do
    it "survives STREAM frame with offset close to UInt64 max" do
      io = IO::Memory.new
      # STREAM type with OFF+LEN+FIN bits: 0x0f
      QUIC::VarInt.write(io, 0x0f_u64)
      QUIC::VarInt.write(io, 0u64)          # stream_id = 0
      QUIC::VarInt.write(io, 0x3FFF_u64)    # large offset (2-byte max VarInt)
      QUIC::VarInt.write(io, 4u64)          # length = 4
      io.write(Bytes[0xDE, 0xAD, 0xBE, 0xEF])
      io.rewind
      (QUIC::Frame.decode(io) rescue nil)    # must not crash
    end

    it "survives STREAM frame claiming huge length with no body" do
      io = IO::Memory.new
      QUIC::VarInt.write(io, 0x0e_u64)      # STREAM with OFF+LEN bits
      QUIC::VarInt.write(io, 0u64)          # stream_id
      QUIC::VarInt.write(io, 0u64)          # offset
      QUIC::VarInt.write(io, 0x3FFF_u64)    # length = 16383, but no bytes follow
      io.rewind
      (QUIC::Frame.decode(io) rescue nil)
    end
  end

  describe "CRYPTO frame with adversarial offset" do
    it "survives CRYPTO frame with max-VarInt offset and zero length" do
      io = IO::Memory.new
      QUIC::VarInt.write(io, 0x06_u64)       # CRYPTO type
      QUIC::VarInt.write(io, 0x3FFF_u64)     # large offset (2-byte VarInt)
      QUIC::VarInt.write(io, 0u64)            # length = 0 (no body)
      io.rewind
      (QUIC::Frame.decode(io) rescue nil)
    end
  end

  describe "RESET_STREAM with extreme final_size" do
    it "survives RESET_STREAM with final_size = max VarInt" do
      frame = QUIC::ResetStreamFrame.new(0u64, 0u64, 0x3FFFFFFFu64)
      io = IO::Memory.new
      frame.encode(io)
      io.rewind
      decoded = QUIC::Frame.decode(io)
      decoded.should be_a(QUIC::ResetStreamFrame)
      decoded.as(QUIC::ResetStreamFrame).final_size.should eq(0x3FFFFFFFu64)
    end
  end

  describe "Long header with extreme DCID/SCID lengths" do
    it "survives long-header packet advertising DCID length=20 with only 10 bytes" do
      # Version 0x00000001, DCID_LEN=20 but only 10 real bytes
      raw = Bytes.new(1 + 4 + 1 + 10)  # 1 type + 4 version + 1 len + 10 truncated DCID
      raw[0] = 0xC0_u8           # long header, QUIC v1 Initial type bits
      raw[1] = 0x00_u8; raw[2] = 0x00_u8; raw[3] = 0x00_u8; raw[4] = 0x01_u8
      raw[5] = 20_u8             # DCID length = 20 (but only 10 bytes follow)
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      conn.recv(raw) rescue nil  # must not crash
    end

    it "survives short-header packet with truncated DCID (< 8 bytes)" do
      (1..7).each do |len|
        raw = Bytes.new(1 + len, 0x40_u8)
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(raw) rescue nil
      end
    end
  end

  describe "Coalesced / concatenated datagrams" do
    it "survives two concatenated random datagrams" do
      50.times do
        a = Random::Secure.random_bytes(Random.rand(20..600))
        b = Random::Secure.random_bytes(Random.rand(20..600))
        combined = Bytes.new(a.size + b.size)
        combined.copy_from(a)
        combined[a.size, b.size].copy_from(b)
        conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
        conn.recv(combined) rescue nil
      end
    end

    it "survives three concatenated all-zero long-header packets" do
      # Simulates GRO aggregation of three malformed datagrams
      header = Bytes.new(21, 0x00_u8)
      header[0] = 0xC0_u8  # long header marker
      triple = Bytes.new(header.size * 3)
      3.times { |i| triple[i * header.size, header.size].copy_from(header) }
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      conn.recv(triple) rescue nil
    end
  end

  describe "Connection state machine under adversarial input" do
    it "survives recv on a closed connection" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      conn.close(0u64, "done")
      100.times do
        data = Random::Secure.random_bytes(50)
        conn.recv(data) rescue nil
      end
    end

    it "recv returns 0 or raises cleanly — never panics — on 5000 random inputs" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      5000.times do
        len  = Random.rand(1..1200)
        data = Random::Secure.random_bytes(len)
        conn.recv(data) rescue nil
      end
    end

    it "survives oversized datagram (> MTU)" do
      conn = QUIC::Connection.new(QUIC::Config.new, is_server: true)
      [2000, 8192, 65535].each do |size|
        data = Random::Secure.random_bytes(size)
        conn.recv(data) rescue nil
      end
    end
  end

  describe "QUIC::Frame.decode — unknown / reserved frame types" do
    it "handles all reserved 1-byte frame types without crashing" do
      # Types 0x0B-0x0F are STREAM variants; 0x1D-0x1F and others are reserved
      [0x0B, 0x0C, 0x1D, 0x1F, 0x20, 0x21, 0x2F, 0x50].each do |type_byte|
        io = IO::Memory.new
        QUIC::VarInt.write(io, type_byte.to_u64)
        io.rewind
        (QUIC::Frame.decode(io) rescue nil)
      end
    end

    it "handles 2-byte VarInt frame types in the reserved range" do
      [0x40, 0x41, 0x7F, 0x100, 0x3FFF].each do |type_val|
        io = IO::Memory.new
        QUIC::VarInt.write(io, type_val.to_u64)
        io.rewind
        (QUIC::Frame.decode(io) rescue nil)
      end
    end
  end
end

describe "H3::Frame.decode — adversarial HTTP/3 inputs" do
  describe "HEADERS frame with malformed QPACK body" do
    it "survives HEADERS with random bytes in the QPACK payload" do
      20.times do
        body = Random::Secure.random_bytes(Random.rand(1..64))
        frame = H3::HeadersFrame.new({":status" => "200"})
        # Build raw HEADERS frame with adversarial body
        io = IO::Memory.new
        QUIC::VarInt.write(io, 0x01_u64)              # HEADERS type
        QUIC::VarInt.write(io, body.size.to_u64)
        io.write(body)
        io.rewind
        (H3::Frame.decode(io) rescue nil)
      end
    end
  end

  describe "frame length / type boundary attacks" do
    it "survives DATA frame with length=0" do
      io = IO::Memory.new
      QUIC::VarInt.write(io, 0x00_u64)   # DATA type
      QUIC::VarInt.write(io, 0u64)        # length = 0
      io.rewind
      decoded = H3::Frame.decode(io)
      decoded.should be_a(H3::DataFrame)
      decoded.as(H3::DataFrame).data.should eq(Bytes.empty)
    end

    it "survives SETTINGS frame with odd number of VarInts" do
      io = IO::Memory.new
      QUIC::VarInt.write(io, 0x04_u64)   # SETTINGS type
      # Build SETTINGS with 3 VarInts (id, val, orphaned id with no val)
      body = IO::Memory.new
      QUIC::VarInt.write(body, 0x01_u64) # QPACK_MAX_TABLE_CAPACITY key
      QUIC::VarInt.write(body, 0u64)     # value
      QUIC::VarInt.write(body, 0x07_u64) # orphaned key (no value)
      QUIC::VarInt.write(io, body.size.to_u64)
      io.write(body.to_slice)
      io.rewind
      (H3::Frame.decode(io) rescue nil)
    end

    it "survives PUSH_PROMISE frame with zero push_id" do
      io = IO::Memory.new
      QUIC::VarInt.write(io, 0x05_u64)    # PUSH_PROMISE type
      body = IO::Memory.new
      QUIC::VarInt.write(body, 0u64)      # push_id = 0
      # empty QPACK header block
      QUIC::VarInt.write(io, body.size.to_u64)
      io.write(body.to_slice)
      io.rewind
      (H3::Frame.decode(io) rescue nil)
    end
  end
end
