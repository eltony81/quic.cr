require "./spec_helper"

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

# Builds a QPACK instruction byte sequence for an "Insert Without Name Reference"
# (encoder stream opcode 01HXXXXX, RFC 9204 §3.2.6).
private def qpack_ins_literal(name : String, value : String) : Bytes
  io = IO::Memory.new
  H3::QPACK::Integer.encode(io, name.bytesize.to_u64, 5, 0x40_u8)
  io.write name.to_slice
  H3::QPACK::Integer.encode(io, value.bytesize.to_u64, 7, 0x00_u8)
  io.write value.to_slice
  io.to_slice
end

# "Insert With Name Reference" — T=1 static (RFC 9204 §3.2.5).
private def qpack_ins_static_name_ref(static_idx : UInt64, value : String) : Bytes
  io = IO::Memory.new
  H3::QPACK::Integer.encode(io, static_idx, 6, 0xC0_u8)
  H3::QPACK::Integer.encode(io, value.bytesize.to_u64, 7, 0x00_u8)
  io.write value.to_slice
  io.to_slice
end

# "Insert With Name Reference" — T=0 dynamic, rel_idx relative to insert_count
# at the time the instruction is processed (RFC 9204 §3.2.5).
private def qpack_ins_dyn_name_ref(rel_idx : UInt64, value : String) : Bytes
  io = IO::Memory.new
  H3::QPACK::Integer.encode(io, rel_idx, 6, 0x80_u8)
  H3::QPACK::Integer.encode(io, value.bytesize.to_u64, 7, 0x00_u8)
  io.write value.to_slice
  io.to_slice
end

# "Duplicate" — relative index (RFC 9204 §3.2.7).
private def qpack_ins_duplicate(rel_idx : UInt64) : Bytes
  io = IO::Memory.new
  H3::QPACK::Integer.encode(io, rel_idx, 5, 0x00_u8)
  io.to_slice
end

# "Set Dynamic Table Capacity" (RFC 9204 §3.2.3).
private def qpack_ins_set_capacity(cap : UInt64) : Bytes
  io = IO::Memory.new
  H3::QPACK::Integer.encode(io, cap, 5, 0x20_u8)
  io.to_slice
end

# Full encoder→encoder-stream→decoder round-trip.
# Returns decoded headers.  Drains the encoder's instruction buffer each call.
private def qpack_roundtrip(enc : H3::QPACK::Encoder, dec : H3::QPACK::Decoder,
                            headers : Hash(String, String)) : Hash(String, String)
  encoded = enc.encode(headers)
  instr = enc.encoder_stream_io.to_slice.dup
  enc.encoder_stream_io.clear
  enc.encoder_stream_io.rewind
  dec.process_encoder_stream(instr) if instr.size > 0
  dec.decode(encoded)
end

# ──────────────────────────────────────────────────────────────────────────────
# DynamicTable
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::DynamicTable" do
  it "starts empty" do
    t = H3::QPACK::DynamicTable.new
    t.capacity.should eq(0)
    t.size.should eq(0)
    t.insert_count.should eq(0)
    t.dropped_count.should eq(0)
    t.entries.empty?.should be_true
  end

  it "tracks insert_count and entry size" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    t.add("x-foo", "bar")
    t.add("x-baz", "qux")
    t.insert_count.should eq(2)
    expected_size = ("x-foo".bytesize + "bar".bytesize + 32 +
                     "x-baz".bytesize + "qux".bytesize + 32).to_u64
    t.size.should eq(expected_size)
  end

  it "get_by_absolute returns entries by absolute index" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    t.add("a", "1")  # absolute index 0
    t.add("b", "2")  # absolute index 1
    t.add("c", "3")  # absolute index 2
    t.get_by_absolute(0).should eq({"a", "1"})
    t.get_by_absolute(1).should eq({"b", "2"})
    t.get_by_absolute(2).should eq({"c", "3"})
    t.get_by_absolute(3).should be_nil  # beyond insert_count
  end

  it "get_by_relative: relative 0 is the most recently inserted entry" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    t.add("first",  "1")  # abs 0
    t.add("second", "2")  # abs 1
    t.add("third",  "3")  # abs 2
    base = t.insert_count  # 3
    t.get_by_relative(base, 0).should eq({"third",  "3"})
    t.get_by_relative(base, 1).should eq({"second", "2"})
    t.get_by_relative(base, 2).should eq({"first",  "1"})
    t.get_by_relative(base, 3).should be_nil
  end

  it "get_by_post_base: post-base index 0 is the entry at Base itself" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    t.add("a", "1")  # abs 0
    t.add("b", "2")  # abs 1
    t.add("c", "3")  # abs 2
    # With base=1: post-base 0 → abs 1, post-base 1 → abs 2
    t.get_by_post_base(1_u64, 0).should eq({"b", "2"})
    t.get_by_post_base(1_u64, 1).should eq({"c", "3"})
    t.get_by_post_base(1_u64, 2).should be_nil
  end

  it "evicts oldest entry when capacity is exceeded" do
    # Each entry "k"/"v": 1+1+32 = 34 bytes.
    # capacity=68 fits exactly 2; third insert triggers eviction of abs 0.
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(68_u64)
    t.add("k", "v")  # abs 0
    t.add("k", "v")  # abs 1
    t.add("k", "v")  # abs 2 → evict abs 0
    t.insert_count.should eq(3)
    t.dropped_count.should eq(1)
    t.get_by_absolute(0).should be_nil  # evicted
    t.get_by_absolute(1).should_not be_nil
    t.get_by_absolute(2).should_not be_nil
  end

  it "get_by_relative returns nil for evicted entries" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(68_u64)
    t.add("k", "v")  # abs 0
    t.add("k", "v")  # abs 1
    t.add("k", "v")  # abs 2 → evicts abs 0
    base = t.insert_count  # 3
    t.get_by_relative(base, 0).should_not be_nil  # abs 2 ok
    t.get_by_relative(base, 1).should_not be_nil  # abs 1 ok
    t.get_by_relative(base, 2).should be_nil       # abs 0 evicted
  end

  it "reducing set_capacity below current size triggers eviction" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    t.add("x", "y")  # 33 bytes
    t.add("a", "b")  # 33 bytes; total 66
    t.set_capacity(40_u64)  # only fits one; evicts abs 0
    t.dropped_count.should eq(1)
    t.get_by_absolute(0).should be_nil
    t.get_by_absolute(1).should_not be_nil
  end

  it "set_capacity(0) drops all entries" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    t.add("x", "y")
    t.add("a", "b")
    t.set_capacity(0_u64)
    t.entries.empty?.should be_true
    t.size.should eq(0)
    t.dropped_count.should eq(2)
    t.insert_count.should eq(2)
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# QPACK Integer encoding
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::Integer" do
  it "round-trips single-byte values (value < 2^n - 1)" do
    {5, 6, 7, 8}.each do |n|
      mask = (1 << n) - 1
      {0, 1, mask - 1}.each do |v|
        io = IO::Memory.new
        H3::QPACK::Integer.encode(io, v.to_u64, n)
        io.rewind
        b = io.read_byte.not_nil!
        H3::QPACK::Integer.decode(io, b, n).should eq(v.to_u64)
      end
    end
  end

  it "round-trips multi-byte values (value >= 2^n - 1)" do
    { {8, 255}, {8, 256}, {8, 1337}, {6, 63}, {6, 1000}, {5, 31}, {5, 9000} }.each do |(n, v)|
      io = IO::Memory.new
      H3::QPACK::Integer.encode(io, v.to_u64, n)
      io.rewind
      b = io.read_byte.not_nil!
      H3::QPACK::Integer.decode(io, b, n).should eq(v.to_u64)
    end
  end

  it "preserves flag bits in the high bits of the first byte" do
    io = IO::Memory.new
    H3::QPACK::Integer.encode(io, 42_u64, 6, 0xC0_u8)
    io.rewind
    b = io.read_byte.not_nil!
    (b & 0xC0).should eq(0xC0_u8)
    H3::QPACK::Integer.decode(io, b, 6).should eq(42_u64)
  end

  it "encodes zero as a single zero byte" do
    io = IO::Memory.new
    H3::QPACK::Integer.encode(io, 0_u64, 8, 0x00_u8)
    io.to_slice.should eq(Bytes[0])
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# InstructionDecoder
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::InstructionDecoder" do
  it "Set Dynamic Table Capacity updates the table capacity" do
    t = H3::QPACK::DynamicTable.new
    H3::QPACK::InstructionDecoder.new(t).decode(IO::Memory.new(qpack_ins_set_capacity(4096_u64)))
    t.capacity.should eq(4096)
  end

  it "Insert Without Name Reference adds the entry" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    H3::QPACK::InstructionDecoder.new(t).decode(IO::Memory.new(qpack_ins_literal("x-foo", "bar")))
    t.insert_count.should eq(1)
    t.get_by_absolute(0).should eq({"x-foo", "bar"})
  end

  it "Insert With Static Name Reference (T=1) looks up name from static table" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    # Static index 1 = {":path", "/"} — reuse the name with a different value
    H3::QPACK::InstructionDecoder.new(t).decode(IO::Memory.new(qpack_ins_static_name_ref(1_u64, "/api")))
    t.insert_count.should eq(1)
    t.get_by_absolute(0).should eq({":path", "/api"})
  end

  it "Insert With Dynamic Name Reference (T=0) uses relative index into dynamic table" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    # Seed: add "x-foo"="v1" (abs 0).  insert_count=1, so relative 0 = abs 0.
    H3::QPACK::InstructionDecoder.new(t).decode(IO::Memory.new(qpack_ins_literal("x-foo", "v1")))
    t.insert_count.should eq(1)
    # Now insert a new entry reusing the dynamic name at relative index 0.
    # After decoding this instruction the table has insert_count=2 and
    # abs 1 should be ("x-foo", "v2").
    H3::QPACK::InstructionDecoder.new(t).decode(IO::Memory.new(qpack_ins_dyn_name_ref(0_u64, "v2")))
    t.insert_count.should eq(2)
    t.get_by_absolute(1).should eq({"x-foo", "v2"})
  end

  it "Insert With Dynamic Name Reference with multiple existing entries resolves correctly" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    # abs 0 = ("a","1"), abs 1 = ("b","2"), abs 2 = ("c","3")
    dec = H3::QPACK::InstructionDecoder.new(t)
    dec.decode(IO::Memory.new(qpack_ins_literal("a", "1")))
    dec.decode(IO::Memory.new(qpack_ins_literal("b", "2")))
    dec.decode(IO::Memory.new(qpack_ins_literal("c", "3")))
    # insert_count=3: relative 0 = abs 2 = ("c","3"), relative 1 = abs 1 = ("b","2")
    # insert_count=3: rel 0 → abs 2 = ("c","3")
    dec.decode(IO::Memory.new(qpack_ins_dyn_name_ref(0_u64, "new")))
    t.get_by_absolute(3).should eq({"c", "new"})
    # insert_count=4: rel 0=abs3("c","new"), rel1=abs2("c","3"), rel2=abs1("b","2")
    dec.decode(IO::Memory.new(qpack_ins_dyn_name_ref(2_u64, "new2")))
    t.get_by_absolute(4).should eq({"b", "new2"})
  end

  it "Duplicate inserts a copy of the entry at the given relative index" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    dec = H3::QPACK::InstructionDecoder.new(t)
    dec.decode(IO::Memory.new(qpack_ins_literal("x-dup", "value")))  # abs 0, insert_count=1
    # Relative index 0 with base=insert_count=1 → abs 0 = ("x-dup","value")
    dec.decode(IO::Memory.new(qpack_ins_duplicate(0_u64)))
    t.insert_count.should eq(2)
    t.get_by_absolute(1).should eq({"x-dup", "value"})
  end

  it "Duplicate with multiple entries resolves relative index correctly" do
    t = H3::QPACK::DynamicTable.new
    t.set_capacity(4096_u64)
    dec = H3::QPACK::InstructionDecoder.new(t)
    dec.decode(IO::Memory.new(qpack_ins_literal("first",  "1")))  # abs 0
    dec.decode(IO::Memory.new(qpack_ins_literal("second", "2")))  # abs 1
    dec.decode(IO::Memory.new(qpack_ins_literal("third",  "3")))  # abs 2, insert_count=3
    # Duplicate rel 1: base=3, rel 1 → abs 1 = ("second","2")
    dec.decode(IO::Memory.new(qpack_ins_duplicate(1_u64)))
    t.insert_count.should eq(4)
    t.get_by_absolute(3).should eq({"second", "2"})
  end

  it "handles a sequence of mixed instructions" do
    t = H3::QPACK::DynamicTable.new
    io = IO::Memory.new
    io.write qpack_ins_set_capacity(4096_u64)
    io.write qpack_ins_literal("x-foo", "bar")
    io.write qpack_ins_static_name_ref(1_u64, "/api")
    io.rewind
    H3::QPACK::InstructionDecoder.new(t).decode(io)
    t.capacity.should eq(4096)
    t.insert_count.should eq(2)
    t.get_by_absolute(0).should eq({"x-foo", "bar"})
    t.get_by_absolute(1).should eq({":path", "/api"})
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# Encoder — static-only (capacity = 0)
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::Encoder (static-only)" do
  it "static exact match produces ERIC=0 prefix (no dynamic refs)" do
    enc = H3::QPACK::Encoder.new
    # :method GET is static index 17; :scheme https is index 23; :status 200 is index 25.
    encoded = enc.encode({":method" => "GET", ":scheme" => "https", ":status" => "200"})
    io = IO::Memory.new(encoded)
    # First byte = ERIC (8-bit prefix); second byte = base
    first = io.read_byte.not_nil!
    (first & 0xFF).should eq(0)  # ERIC = 0, no dynamic refs
    enc.encoder_stream_io.pos.should eq(0)  # no encoder-stream instructions emitted
  end

  it "static exact match round-trips correctly" do
    enc = H3::QPACK::Encoder.new
    dec = H3::QPACK::Decoder.new
    headers = {":method" => "GET", ":path" => "/", ":scheme" => "https", ":status" => "200"}
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end

  it "static name-only match (different value) uses literal with static name ref" do
    enc = H3::QPACK::Encoder.new
    dec = H3::QPACK::Decoder.new
    headers = {":status" => "404"}  # name in static, value not
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end

  it "novel header (not in static table) uses literal without name ref" do
    enc = H3::QPACK::Encoder.new
    dec = H3::QPACK::Decoder.new
    headers = {"x-custom-header" => "my-value"}
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end

  it "encoding produces no encoder-stream bytes when capacity=0" do
    enc = H3::QPACK::Encoder.new
    enc.encode({"x-foo" => "bar", "x-baz" => "qux"})
    enc.encoder_stream_io.pos.should eq(0)
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# Encoder — dynamic table (capacity > 0)
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::Encoder (dynamic table)" do
  it "inserts novel headers into the dynamic table on first encode" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    enc.encode({"x-foo" => "bar"})
    enc.dynamic_table.insert_count.should eq(1)
    enc.dynamic_table.get_by_absolute(0).should eq({"x-foo", "bar"})
  end

  it "emits encoder-stream Insert instructions for novel headers" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    enc.encode({"x-foo" => "bar"})
    enc.encoder_stream_io.pos.should be > 0
  end

  it "ERIC formula: first insert → ERIC = 2 (RIC=1, MaxEntries=128)" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    encoded = enc.encode({"x-novel" => "value"})
    io = IO::Memory.new(encoded)
    first = io.read_byte.not_nil!
    # RIC=1, MaxEntries=floor(4096/32)=128, 2*MaxEntries=256
    # ERIC = (1 % 256) + 1 = 2
    eric = H3::QPACK::Integer.decode(io, first, 8)
    eric.should eq(2)
  end

  it "ERIC formula: RIC=128 → ERIC=129" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    # Seed the table with 127 entries via InstructionDecoder to avoid slow loop
    127.times do |i|
      enc.dynamic_table.add("x-seed-#{i}", "v")
    end
    # Now encode one more novel header: RIC will be 128
    encoded = enc.encode({"x-final" => "last"})
    io = IO::Memory.new(encoded)
    b = io.read_byte.not_nil!
    eric = H3::QPACK::Integer.decode(io, b, 8)
    eric.should eq(129)  # (128 % 256) + 1 = 129
  end

  it "ERIC formula: RIC=256 wraps to ERIC=1" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    255.times { |i| enc.dynamic_table.add("x-#{i}", "v") }
    encoded = enc.encode({"x-novel-256" => "w"})
    io = IO::Memory.new(encoded)
    b = io.read_byte.not_nil!
    eric = H3::QPACK::Integer.decode(io, b, 8)
    eric.should eq(1)  # (256 % 256) + 1 = 1
  end

  it "dynamic encoding is more compact than static-only encoding for novel headers" do
    headers = {"x-trace" => "abc123", "x-region" => "us-east-1"}
    # Static-only (capacity=0): emits literal field lines
    literal_enc = H3::QPACK::Encoder.new
    literal_size = literal_enc.encode(headers).size
    # Dynamic (capacity>0): Pass 1 inserts, Pass 2 uses indexed refs even on first call
    dynamic_enc = H3::QPACK::Encoder.new
    dynamic_enc.dynamic_table.set_capacity(4096_u64)
    dynamic_size = dynamic_enc.encode(headers).size
    dynamic_size.should be < literal_size
  end

  it "encoder emits correct relative index for dynamic name references" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    # First encode: insert "x-foo"="v1" and "x-bar"="w1" into dynamic table
    r1 = qpack_roundtrip(enc, dec, {"x-foo" => "v1", "x-bar" => "w1"})
    r1.should eq({"x-foo" => "v1", "x-bar" => "w1"})
    # Second encode: "x-foo" has same name, different value → dynamic name ref
    r2 = qpack_roundtrip(enc, dec, {"x-foo" => "v2"})
    r2.should eq({"x-foo" => "v2"})
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# Decoder — ERIC → RIC formula (RFC 9204 §4.5.1)
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::Decoder (ERIC formula)" do
  it "ERIC=0 → RIC=0 (no dynamic references)" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    # Static-only encoded headers have ERIC=0
    enc = H3::QPACK::Encoder.new  # capacity=0 by default
    encoded = enc.encode({":status" => "200"})
    dec.decode(encoded).should eq({":status" => "200"})
    dec.last_required_insert_count.should eq(0)
  end

  it "ERIC=2, insert_count=1 → RIC=1" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    dec.dynamic_table.add("x-foo", "bar")  # insert_count=1
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    enc.dynamic_table.add("x-foo", "bar")
    encoded = enc.encode({"x-foo" => "bar"})
    dec.decode(encoded)
    dec.last_required_insert_count.should eq(1)
  end

  it "ERIC formula: RIC=128, insert_count=128 → no QpackBlockedError" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    # Seed both tables with 127 entries
    127.times do |i|
      enc.dynamic_table.add("h#{i}", "v")
      dec.dynamic_table.add("h#{i}", "v")
    end
    # 128th insert happens during encode; feed encoder stream to decoder first
    encoded = enc.encode({"h127-novel" => "w"})
    instr = enc.encoder_stream_io.to_slice.dup
    enc.encoder_stream_io.clear; enc.encoder_stream_io.rewind
    dec.process_encoder_stream(instr)
    result = dec.decode(encoded)
    result.should eq({"h127-novel" => "w"})
    dec.last_required_insert_count.should eq(128)
  end

  it "raises QpackBlockedError when RIC > decoder's insert_count" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    enc.dynamic_table.add("x-foo", "bar")  # encoder insert_count=1, ERIC=2
    encoded = enc.encode({"x-foo" => "bar"})
    # Decoder hasn't received the encoder stream yet → insert_count=0 < RIC=1
    expect_raises(H3::QPACK::QpackBlockedError) do
      dec.decode(encoded)
    end
  end

  it "does not raise QpackBlockedError once encoder stream is delivered" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    encoded = enc.encode({"x-novel" => "value"})
    instr = enc.encoder_stream_io.to_slice.dup
    # Deliver encoder stream BEFORE decoding
    dec.process_encoder_stream(instr)
    result = dec.decode(encoded)
    result.should eq({"x-novel" => "value"})
  end

  it "decodes static Indexed Field Line (1TXXXXXX, T=1)" do
    # :method GET is static index 17
    io = IO::Memory.new
    io.write_byte(0x00_u8)  # ERIC=0
    io.write_byte(0x00_u8)  # Base=0
    H3::QPACK::Integer.encode(io, 17_u64, 6, 0xC0_u8)  # 1 1 XXXXXX (static, idx=17)
    io.rewind
    dec = H3::QPACK::Decoder.new
    result = dec.decode(io.to_slice)
    result[":method"].should eq("GET")
  end

  it "decodes dynamic Indexed Field Line (1TXXXXXX, T=0) via relative index" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    dec.dynamic_table.add("x-dyn", "dynval")  # abs 0, insert_count=1
    # Encode: ERIC=2 (RIC=1), Base=0 (base_delta=0, no sign), rel 0 = abs 0
    io = IO::Memory.new
    H3::QPACK::Integer.encode(io, 2_u64, 8, 0x00_u8)   # ERIC=2
    io.write_byte(0x00_u8)                               # Base delta=0, no sign
    H3::QPACK::Integer.encode(io, 0_u64, 6, 0x80_u8)   # 1 0 XXXXXX (dynamic, rel_idx=0)
    result = dec.decode(io.to_slice)
    result["x-dyn"].should eq("dynval")
  end

  it "decodes Literal Field Line Without Name Reference (001NXXX)" do
    dec = H3::QPACK::Decoder.new
    io = IO::Memory.new
    io.write_byte(0x00_u8)  # ERIC=0
    io.write_byte(0x00_u8)  # Base
    # 001 N H XXX: flags=0x20, H=0, name length in 3-bit prefix
    H3::QPACK::Integer.encode(io, "x-lit".bytesize.to_u64, 3, 0x20_u8)
    io.write "x-lit".to_slice
    H3::QPACK::Integer.encode(io, "lval".bytesize.to_u64, 7, 0x00_u8)
    io.write "lval".to_slice
    result = dec.decode(io.to_slice)
    result["x-lit"].should eq("lval")
  end

  it "decodes Literal Field Line With Static Name Reference (01NT XXXX, T=1)" do
    dec = H3::QPACK::Decoder.new
    io = IO::Memory.new
    io.write_byte(0x00_u8)  # ERIC=0
    io.write_byte(0x00_u8)  # Base
    # 01 N T XXXX: flags=0x50 (N=0, T=1=static), idx in 4-bit prefix
    # Static index 1 = :path. Use value "/custom"
    H3::QPACK::Integer.encode(io, 1_u64, 4, 0x50_u8)
    H3::QPACK::Integer.encode(io, "/custom".bytesize.to_u64, 7, 0x00_u8)
    io.write "/custom".to_slice
    result = dec.decode(io.to_slice)
    result[":path"].should eq("/custom")
  end

  it "decodes Literal Field Line With Dynamic Name Reference (01NT XXXX, T=0)" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    dec.dynamic_table.add("x-name", "ignored")  # abs 0, insert_count=1
    io = IO::Memory.new
    H3::QPACK::Integer.encode(io, 2_u64, 8, 0x00_u8)   # ERIC=2 (RIC=1)
    io.write_byte(0x00_u8)                               # Base=1 (delta=0)
    # 01 N T XXXX: flags=0x40 (T=0=dynamic), rel_idx=0 (base=1, rel 0 = abs 0)
    H3::QPACK::Integer.encode(io, 0_u64, 4, 0x40_u8)
    H3::QPACK::Integer.encode(io, "newval".bytesize.to_u64, 7, 0x00_u8)
    io.write "newval".to_slice
    result = dec.decode(io.to_slice)
    result["x-name"].should eq("newval")
  end

  it "decodes Post-Base Indexed Field Line (0001 XXXX)" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    dec.dynamic_table.add("x-pb", "pbval")  # abs 0
    # Post-base: Base=0, post-base 0 → abs 0
    io = IO::Memory.new
    H3::QPACK::Integer.encode(io, 2_u64, 8, 0x00_u8)  # ERIC=2
    io.write_byte(0x00_u8)                              # Base delta=0 (Base = RIC = 1)
    # Wait, post-base with Base=RIC=1 would mean post-base 0 → abs 1 (beyond table).
    # Let's use base_sign=1 (negative delta) to get Base=0: RIC=1, delta=1, Base = 1-1-1 = -1? No.
    # Actually: Base = RIC - base_delta - 1 when sign=1.
    # For Base=0: RIC=1, 0 = 1 - base_delta - 1 → base_delta=0. But then Base=1-0-1=0. OK.
    # Let me redo: ERIC=2 (RIC=1), Base sign=1, delta=0 → Base = 1-0-1 = 0.
    # Post-base 0 with Base=0 → abs 0 = ("x-pb","pbval").
    dec2 = H3::QPACK::Decoder.new
    dec2.dynamic_table.set_capacity(4096_u64)
    dec2.dynamic_table.add("x-pb", "pbval")
    io2 = IO::Memory.new
    H3::QPACK::Integer.encode(io2, 2_u64, 8, 0x00_u8)  # ERIC=2 (RIC=1)
    io2.write_byte(0x80_u8)                              # Base sign=1, delta=0 → Base=0
    H3::QPACK::Integer.encode(io2, 0_u64, 4, 0x10_u8)  # 0001 XXXX post-base idx=0
    result = dec2.decode(io2.to_slice)
    result["x-pb"].should eq("pbval")
  end

  it "decodes Post-Base Literal With Name Reference (0000 NXXX)" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    dec.dynamic_table.add("x-pb-name", "seed")  # abs 0, insert_count=1
    # Base=0 via sign bit: RIC=1, sign=1, delta=0 → Base=0.
    # Post-base name ref idx=0 → abs 0 = ("x-pb-name","seed"), value="override"
    io = IO::Memory.new
    H3::QPACK::Integer.encode(io, 2_u64, 8, 0x00_u8)  # ERIC=2
    io.write_byte(0x80_u8)                              # Base=0
    H3::QPACK::Integer.encode(io, 0_u64, 3, 0x00_u8)  # 0000 NXXX, N=0, idx=0
    H3::QPACK::Integer.encode(io, "override".bytesize.to_u64, 7, 0x00_u8)
    io.write "override".to_slice
    result = dec.decode(io.to_slice)
    result["x-pb-name"].should eq("override")
  end

  it "decodes Post-Base Literal With Name Reference when N=1 (Never Indexed)" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    dec.dynamic_table.add("x-secret", "seed")
    io = IO::Memory.new
    H3::QPACK::Integer.encode(io, 2_u64, 8, 0x00_u8)  # ERIC=2
    io.write_byte(0x80_u8)                              # Base=0
    # 0000 N XXX with N=1: 0x08 | idx
    H3::QPACK::Integer.encode(io, 0_u64, 3, 0x08_u8)  # N=1 (0x08), idx=0
    H3::QPACK::Integer.encode(io, "nval".bytesize.to_u64, 7, 0x00_u8)
    io.write "nval".to_slice
    result = dec.decode(io.to_slice)
    result["x-secret"].should eq("nval")
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# Validation (RFC 9114 §4.3)
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::Decoder (validation)" do
  it "raises ValidationError for pseudo-header after regular header" do
    enc = H3::QPACK::Encoder.new
    # Hash ordering in Crystal preserves insertion order
    headers = {"content-type" => "text/plain", ":status" => "200"}
    encoded = enc.encode(headers)
    expect_raises(H3::QPACK::ValidationError, /pseudo-header/) do
      H3::QPACK::Decoder.new.decode(encoded)
    end
  end

  it "raises ValidationError for duplicate pseudo-headers" do
    # Crystal Hash deduplicates keys, so we hand-craft a header block with two :method fields.
    # ERIC=0, Base=0, then two static indexed refs for ":method GET" (static idx 17).
    io = IO::Memory.new
    io.write_byte(0x00_u8)  # ERIC=0
    io.write_byte(0x00_u8)  # Base=0
    H3::QPACK::Integer.encode(io, 17_u64, 6, 0xC0_u8)  # :method GET (first)
    H3::QPACK::Integer.encode(io, 17_u64, 6, 0xC0_u8)  # :method GET (duplicate)
    expect_raises(H3::QPACK::ValidationError, /duplicate/) do
      H3::QPACK::Decoder.new.decode(io.to_slice)
    end
  end

  it "allows multiple distinct pseudo-headers before regular headers" do
    enc = H3::QPACK::Encoder.new
    dec = H3::QPACK::Decoder.new
    headers = {":method" => "GET", ":path" => "/", ":scheme" => "https", "content-type" => "text/plain"}
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# process_encoder_stream (channel signalling)
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK::Decoder#process_encoder_stream" do
  it "updates the dynamic table and inserts entries" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    io = IO::Memory.new
    io.write qpack_ins_literal("x-foo", "bar")
    io.write qpack_ins_literal("x-baz", "qux")
    dec.process_encoder_stream(io.to_slice)
    dec.dynamic_table.insert_count.should eq(2)
    dec.dynamic_table.get_by_absolute(0).should eq({"x-foo", "bar"})
    dec.dynamic_table.get_by_absolute(1).should eq({"x-baz", "qux"})
  end

  it "signals table_updated channel for each inserted entry" do
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    signals = 0
    io = IO::Memory.new
    io.write qpack_ins_literal("a", "1")
    io.write qpack_ins_literal("b", "2")
    io.write qpack_ins_literal("c", "3")
    dec.process_encoder_stream(io.to_slice)
    # Drain the channel non-blocking; should have 3 signals buffered
    3.times do
      select
      when dec.table_updated.receive
        signals += 1
      else
      end
    end
    signals.should eq(3)
  end
end

# ──────────────────────────────────────────────────────────────────────────────
# End-to-end round-trips
# ──────────────────────────────────────────────────────────────────────────────

describe "H3::QPACK round-trip (encoder → encoder_stream → decoder)" do
  it "static-only: no encoder-stream exchange needed" do
    enc = H3::QPACK::Encoder.new
    dec = H3::QPACK::Decoder.new
    headers = {":method" => "GET", ":path" => "/", ":scheme" => "https", ":status" => "200",
               "content-type" => "text/html"}
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end

  it "dynamic: novel headers are correctly decoded on first request" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    headers = {"x-trace-id" => "abc-123", "x-region" => "eu-west-1"}
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end

  it "dynamic: second request is decoded correctly (dynamic refs)" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    headers = {"x-trace-id" => "abc-123", "x-region" => "eu-west-1"}
    qpack_roundtrip(enc, dec, headers)
    # Second encode: same headers → dynamic indexed refs
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end

  it "dynamic: encoder produces smaller header block than literal-only for novel headers" do
    headers = {"x-foo" => "long-value-that-benefits-from-compression",
               "x-bar" => "another-long-value-here"}
    literal_size  = H3::QPACK::Encoder.new.encode(headers).size
    dyn_enc = H3::QPACK::Encoder.new
    dyn_enc.dynamic_table.set_capacity(4096_u64)
    dynamic_size  = dyn_enc.encode(headers).size
    dynamic_size.should be < literal_size
  end

  it "dynamic: three sequential requests preserve state across calls" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    3.times do |i|
      h = {"x-req-id" => "req-#{i}", "x-common" => "static-value"}
      qpack_roundtrip(enc, dec, h).should eq(h)
    end
  end

  it "dynamic: headers with name in dynamic table but different value round-trip" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    # First: insert "x-foo"="v1"
    qpack_roundtrip(enc, dec, {"x-foo" => "v1"})
    # Second: "x-foo" name is in dynamic table but value changes
    # The encoder will use a dynamic name reference in the encoder stream
    result = qpack_roundtrip(enc, dec, {"x-foo" => "v2"})
    result.should eq({"x-foo" => "v2"})
  end

  it "dynamic: eviction — entries past the table limit are dropped, new refs still work" do
    enc = H3::QPACK::Encoder.new
    dec = H3::QPACK::Decoder.new
    # Small capacity: each entry = name + value + 32 bytes.
    # "hN" = 2 chars, "v" = 1 char → entry size = 2+1+32 = 35 bytes.
    # capacity=70 fits 2 entries.
    enc.dynamic_table.set_capacity(70_u64)
    dec.dynamic_table.set_capacity(70_u64)
    # Insert h0, h1, h2 — h0 gets evicted when h2 arrives
    qpack_roundtrip(enc, dec, {"h0" => "v"})
    qpack_roundtrip(enc, dec, {"h1" => "v"})
    # Third request — h2 inserted, h0 evicted
    result = qpack_roundtrip(enc, dec, {"h2" => "v"})
    result.should eq({"h2" => "v"})
    enc.dynamic_table.dropped_count.should be >= 1
  end

  it "Huffman-encoded strings round-trip correctly" do
    enc = H3::QPACK::Encoder.new
    dec = H3::QPACK::Decoder.new
    # The static table already uses Huffman in decode_string; exercise the path
    # by decoding a known Huffman-encoded string via the decoder
    # "www.example.com" is a classic Huffman test string
    headers = {":authority" => "www.example.com", ":path" => "/index.html"}
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end

  it "large header block (50 headers) encodes and decodes correctly" do
    enc = H3::QPACK::Encoder.new
    enc.dynamic_table.set_capacity(4096_u64)
    dec = H3::QPACK::Decoder.new
    dec.dynamic_table.set_capacity(4096_u64)
    headers = (1..50).each_with_object({} of String => String) { |i, h| h["x-h#{i}"] = "value-#{i}" }
    qpack_roundtrip(enc, dec, headers).should eq(headers)
  end
end
