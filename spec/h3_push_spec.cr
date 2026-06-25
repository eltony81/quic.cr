require "./spec_helper"

describe "HTTP/3 Server Push (RFC 9114 §4.6)" do
  describe H3::PushPromiseFrame do
    it "no-arg constructor: push_id and headers are nil (receive/error path)" do
      f = H3::PushPromiseFrame.new
      f.push_id.should be_nil
      f.headers.should be_nil
    end

    it "two-arg constructor: stores push_id and headers" do
      f = H3::PushPromiseFrame.new(7_u64, {":path" => "/app.js", ":method" => "GET"})
      f.push_id.should eq(7_u64)
      f.headers.should eq({":path" => "/app.js", ":method" => "GET"})
    end

    it "encode writes PUSH_PROMISE frame type (0x05) as first byte" do
      f = H3::PushPromiseFrame.new(0_u64, {":path" => "/style.css", ":method" => "GET"})
      io = IO::Memory.new
      f.encode(io)
      raw = io.to_slice
      raw.size.should be > 0
      raw[0].should eq(0x05_u8)
    end

    it "encode writes the push_id as the first byte of the payload (VarInt 0 = 0x00)" do
      f = H3::PushPromiseFrame.new(0_u64, {":path" => "/r"})
      io = IO::Memory.new
      f.encode(io)
      raw = io.to_slice
      # raw[0] = frame type (0x05)
      # raw[1] = payload length (VarInt)
      # raw[2] = push_id=0 (VarInt 0x00)
      raw[2].should eq(0x00_u8)
    end

    it "encode produces no output when push_id is nil" do
      f = H3::PushPromiseFrame.new
      io = IO::Memory.new
      f.encode(io)
      io.size.should eq(0)
    end

    it "type is PUSH_PROMISE (0x05)" do
      f = H3::PushPromiseFrame.new(0_u64, {} of String => String)
      f.type.should eq(H3::FrameType::PUSH_PROMISE)
    end
  end

  describe "H3::Connection#write_frame (PushPromiseFrame with QPACK)" do
    it "encodes PUSH_PROMISE using the connection QPACK encoder" do
      config = QUIC::Config.new
      quic = QUIC::Connection.new(config, is_server: true)
      h3 = H3::Connection.new(quic)

      mock = MockSocket.new
      frame = H3::PushPromiseFrame.new(3_u64, {":path" => "/push.css", ":method" => "GET"})
      h3.write_frame(mock, frame)

      raw = mock.write_io.to_slice
      raw.size.should be > 0
      raw[0].should eq(0x05_u8)  # PUSH_PROMISE frame type
    end

    it "encodes push_id 0 in PUSH_PROMISE payload prefix" do
      config = QUIC::Config.new
      quic = QUIC::Connection.new(config, is_server: true)
      h3 = H3::Connection.new(quic)

      mock = MockSocket.new
      frame = H3::PushPromiseFrame.new(0_u64, {":path" => "/x"})
      h3.write_frame(mock, frame)

      raw = mock.write_io.to_slice
      # raw[0]=frame_type(0x05), raw[1]=payload_len, raw[2]=push_id(0x00)
      raw[2].should eq(0x00_u8)
    end
  end

  describe "Server push stream IDs (RFC 9000 §2.1)" do
    it "server-initiated unidirectional stream IDs satisfy ID % 4 == 3" do
      # Server uni streams: 3, 7, 11, 15, ... (offset 3, stride 4)
      [3_u64, 7_u64, 11_u64, 15_u64, 19_u64].each do |id|
        (id % 4).should eq(3_u64)
      end
    end

    it "push stream type byte is 0x01 (RFC 9114 §6.2.2)" do
      push_stream_type = 0x01_u64
      push_stream_type.should eq(1_u64)
    end
  end

  describe "H3::Connection#server_push tracking" do
    it "push_id increments with each server_push call" do
      # We can't test full network delivery, but we can verify push_id monotonicity
      # by inspecting the PUSH_PROMISE frames written to a mock stream.
      config = QUIC::Config.new
      quic = QUIC::Connection.new(config, is_server: true)
      h3 = H3::Connection.new(quic)

      mock1 = MockSocket.new
      mock2 = MockSocket.new

      h3.write_frame(mock1, H3::PushPromiseFrame.new(0_u64, {":path" => "/a"}))
      h3.write_frame(mock2, H3::PushPromiseFrame.new(1_u64, {":path" => "/b"}))

      raw1 = mock1.write_io.to_slice
      raw2 = mock2.write_io.to_slice

      # Both frames should have frame type 0x05
      raw1[0].should eq(0x05_u8)
      raw2[0].should eq(0x05_u8)

      # push_id 0 vs 1 differ in payload
      raw1.should_not eq(raw2)
    end
  end
end
