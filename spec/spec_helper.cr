require "spec"
require "../src/quic"

class MockSocket < IO
  getter read_io  : IO::Memory
  getter write_io : IO::Memory

  def initialize(read_bytes : Bytes = Bytes.empty)
    @read_io  = IO::Memory.new(read_bytes)
    @write_io = IO::Memory.new
  end

  def read(slice : Bytes) : Int32
    @read_io.read(slice)
  end

  def write(slice : Bytes) : Nil
    @write_io.write(slice)
    nil
  end
end
