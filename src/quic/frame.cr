module QUIC
  enum FrameType : UInt64
    PADDING             = 0x00
    PING                = 0x01
    ACK                 = 0x02
    RESET_STREAM        = 0x04
    STOP_SENDING        = 0x05
    CRYPTO              = 0x06
    NEW_TOKEN           = 0x07
    STREAM              = 0x08 # to 0x0f
    MAX_DATA            = 0x10
    MAX_STREAM_DATA     = 0x11
    MAX_STREAMS         = 0x12
    DATA_BLOCKED        = 0x14
    STREAM_DATA_BLOCKED = 0x15
    STREAMS_BLOCKED     = 0x16
    NEW_CONNECTION_ID   = 0x18
    RETIRE_CONNECTION_ID = 0x19
    PATH_CHALLENGE      = 0x1a
    PATH_RESPONSE       = 0x1b
    CONNECTION_CLOSE    = 0x1c
    HANDSHAKE_DONE      = 0x1e
    DATAGRAM            = 0x30 # RFC 9221
  end

  abstract class Frame
    abstract def type : FrameType
    abstract def encode(io : IO)

    def self.decode(io : IO) : Frame
      type_val = VarInt.decode(io)
      
      case type_val
      when FrameType::PADDING.to_u64
        PaddingFrame.new
      when FrameType::PING.to_u64
        PingFrame.new
      when FrameType::CRYPTO.to_u64
        offset = VarInt.decode(io)
        length = VarInt.decode(io)
        data = Bytes.new(length)
        io.read_fully(data)
        CryptoFrame.new(offset, data)
      when FrameType::NEW_TOKEN.to_u64
        len = VarInt.decode(io)
        token = Bytes.new(len)
        io.read_fully(token)
        NewTokenFrame.new(token)
      when FrameType::RESET_STREAM.to_u64
        ResetStreamFrame.new(VarInt.decode(io), VarInt.decode(io), VarInt.decode(io))
      when FrameType::STOP_SENDING.to_u64
        StopSendingFrame.new(VarInt.decode(io), VarInt.decode(io))
      when FrameType::ACK.to_u64, 0x03_u64
        largest = VarInt.decode(io)
        delay = VarInt.decode(io)
        count = VarInt.decode(io)
        first_range = VarInt.decode(io)
        ack_ranges = [] of {UInt64, UInt64}
        count.times do
          gap = VarInt.decode(io)
          len = VarInt.decode(io)
          ack_ranges << {gap, len}
        end
        if type_val == 0x03_u64
          ect0   = VarInt.decode(io)
          ect1   = VarInt.decode(io)
          ecn_ce = VarInt.decode(io)
          AckFrame.new(largest, delay, first_range, ack_ranges, ect0: ect0, ect1: ect1, ecn_ce: ecn_ce, has_ecn: true)
        else
          AckFrame.new(largest, delay, first_range, ack_ranges)
        end
      when FrameType::MAX_DATA.to_u64
        MaxDataFrame.new(VarInt.decode(io))
      when FrameType::MAX_STREAM_DATA.to_u64
        MaxStreamDataFrame.new(VarInt.decode(io), VarInt.decode(io))
      when FrameType::PATH_CHALLENGE.to_u64
        data = Bytes.new(8)
        io.read_fully(data)
        PathChallengeFrame.new(data)
      when FrameType::PATH_RESPONSE.to_u64
        data = Bytes.new(8)
        io.read_fully(data)
        PathResponseFrame.new(data)
      when FrameType::NEW_CONNECTION_ID.to_u64
        seq = VarInt.decode(io)
        retire = VarInt.decode(io)
        len = io.read_byte || raise BufferTooShort.new
        cid = Bytes.new(len)
        io.read_fully(cid)
        token = Bytes.new(16)
        io.read_fully(token)
        NewConnectionIdFrame.new(seq, retire, cid, token)
      when FrameType::RETIRE_CONNECTION_ID.to_u64
        RetireConnectionIdFrame.new(VarInt.decode(io))
      when FrameType::HANDSHAKE_DONE.to_u64
        HandshakeDoneFrame.new
      when FrameType::DATAGRAM.to_u64, FrameType::DATAGRAM.to_u64 + 1
        has_len = (type_val & 0x01) != 0
        len = has_len ? VarInt.decode(io) : (io.size - io.pos).to_u64
        data = Bytes.new(len)
        io.read_fully(data)
        DatagramFrame.new(data)
      when FrameType::CONNECTION_CLOSE.to_u64  # 0x1c: QUIC-layer close (has frame_type field)
        error_code = VarInt.decode(io)
        frame_type = VarInt.decode(io)
        reason_len = VarInt.decode(io)
        reason = Bytes.new(reason_len)
        io.read_fully(reason)
        ConnectionCloseFrame.new(error_code, frame_type, String.new(reason))
      when 0x1d_u64  # APPLICATION_CLOSE: H3-layer close (no frame_type field per RFC 9000 §19.19)
        error_code = VarInt.decode(io)
        reason_len = VarInt.decode(io)
        reason = Bytes.new(reason_len)
        io.read_fully(reason)
        ConnectionCloseFrame.new(error_code, 0_u64, String.new(reason))
      when 0x08_u64..0x0f_u64
        id = VarInt.decode(io)
        offset = (type_val & 0x04) != 0 ? VarInt.decode(io) : 0_u64
        if (type_val & 0x02) != 0
          length = VarInt.decode(io)
        else
          length = (io.size - io.pos).to_u64
        end
        data = Bytes.new(length)
        io.read_fully(data)
        fin = (type_val & 0x01) != 0
        StreamFrame.new(id, offset, data, fin)
      when FrameType::MAX_DATA.to_u64
        MaxDataFrame.new(VarInt.decode(io))
      when FrameType::MAX_STREAM_DATA.to_u64
        MaxStreamDataFrame.new(VarInt.decode(io), VarInt.decode(io))
      when FrameType::DATA_BLOCKED.to_u64
        DataBlockedFrame.new(VarInt.decode(io))
      when FrameType::STREAM_DATA_BLOCKED.to_u64
        StreamDataBlockedFrame.new(VarInt.decode(io), VarInt.decode(io))
      when 0x12_u64, 0x13_u64 # MAX_STREAMS (bidi / uni)
        MaxStreamsFrame.new(VarInt.decode(io), type_val == 0x12_u64)
      when 0x16_u64, 0x17_u64 # STREAMS_BLOCKED (bidi / uni)
        StreamsBlockedFrame.new(VarInt.decode(io), type_val == 0x16_u64)
      else
        raise ProtocolViolation.new("Unsupported frame type: 0x#{type_val.to_s(16)}")
      end
    end
  end

  class PaddingFrame < Frame
    def type : FrameType; FrameType::PADDING; end
    def encode(io : IO); VarInt.write(io, type.to_u64); end
  end

  class PingFrame < Frame
    def type : FrameType; FrameType::PING; end
    def encode(io : IO); VarInt.write(io, type.to_u64); end
  end

  class CryptoFrame < Frame
    getter offset : UInt64
    getter data : Bytes
    def initialize(@offset, @data); end
    def type : FrameType; FrameType::CRYPTO; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @offset)
      VarInt.write(io, @data.size.to_u64)
      io.write @data
    end
  end

  class MaxDataFrame < Frame
    getter maximum_data : UInt64
    def initialize(@maximum_data); end
    def type : FrameType; FrameType::MAX_DATA; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @maximum_data)
    end
  end

  class MaxStreamDataFrame < Frame
    getter stream_id : UInt64
    getter maximum_stream_data : UInt64
    def initialize(@stream_id, @maximum_stream_data); end
    def type : FrameType; FrameType::MAX_STREAM_DATA; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @stream_id)
      VarInt.write(io, @maximum_stream_data)
    end
  end

  class DataBlockedFrame < Frame
    getter maximum_data : UInt64
    def initialize(@maximum_data); end
    def type : FrameType; FrameType::DATA_BLOCKED; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @maximum_data)
    end
  end

  class StreamDataBlockedFrame < Frame
    getter stream_id : UInt64
    getter maximum_stream_data : UInt64
    def initialize(@stream_id, @maximum_stream_data); end
    def type : FrameType; FrameType::STREAM_DATA_BLOCKED; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @stream_id)
      VarInt.write(io, @maximum_stream_data)
    end
  end

  class NewTokenFrame < Frame
    getter token : Bytes
    def initialize(@token); end
    def type : FrameType; FrameType::NEW_TOKEN; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @token.size.to_u64)
      io.write @token
    end
  end

  class ResetStreamFrame < Frame
    getter id : UInt64
    getter error_code : UInt64
    getter final_size : UInt64
    def initialize(@id, @error_code, @final_size); end
    def type : FrameType; FrameType::RESET_STREAM; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @id)
      VarInt.write(io, @error_code)
      VarInt.write(io, @final_size)
    end
  end

  class StopSendingFrame < Frame
    getter id : UInt64
    getter error_code : UInt64
    def initialize(@id, @error_code); end
    def type : FrameType; FrameType::STOP_SENDING; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @id)
      VarInt.write(io, @error_code)
    end
  end

  class StreamFrame < Frame
    getter id : UInt64
    getter offset : UInt64
    getter data : Bytes
    getter fin : Bool
    def initialize(@id, @offset, @data, @fin = false); end
    def type : FrameType; FrameType::STREAM; end
    def encode(io : IO)
      type_val = 0x08 | 0x04 | 0x02
      type_val |= 0x01 if @fin
      VarInt.write(io, type_val.to_u64)
      VarInt.write(io, @id)
      VarInt.write(io, @offset)
      VarInt.write(io, @data.size.to_u64)
      io.write @data
    end
  end

  class AckFrame < Frame
    getter largest_acknowledged : UInt64
    getter ack_delay : UInt64
    getter first_ack_range : UInt64
    getter ack_ranges : Array({UInt64, UInt64})
    # ECN counts (type 0x03, RFC 9000 §19.3.2)
    getter ect0 : UInt64 = 0_u64
    getter ect1 : UInt64 = 0_u64
    getter ecn_ce : UInt64 = 0_u64
    getter? has_ecn : Bool = false

    def initialize(@largest_acknowledged, @ack_delay, @first_ack_range,
                   @ack_ranges = [] of {UInt64, UInt64},
                   ect0 : UInt64 = 0_u64, ect1 : UInt64 = 0_u64,
                   ecn_ce : UInt64 = 0_u64, has_ecn : Bool = false)
      @ect0 = ect0
      @ect1 = ect1
      @ecn_ce = ecn_ce
      @has_ecn = has_ecn
    end

    def type : FrameType; FrameType::ACK; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @largest_acknowledged)
      VarInt.write(io, @ack_delay)
      VarInt.write(io, @ack_ranges.size.to_u64)
      VarInt.write(io, @first_ack_range)
      @ack_ranges.each do |gap, len|
        VarInt.write(io, gap)
        VarInt.write(io, len)
      end
    end
  end

  class MaxStreamsFrame < Frame
    getter maximum_streams : UInt64
    getter bidirectional : Bool
    def initialize(@maximum_streams, @bidirectional); end
    def type : FrameType; FrameType::MAX_STREAMS; end
    def encode(io : IO)
      VarInt.write(io, @bidirectional ? 0x12_u64 : 0x13_u64)
      VarInt.write(io, @maximum_streams)
    end
  end

  class StreamsBlockedFrame < Frame
    getter maximum_streams : UInt64
    getter bidirectional : Bool
    def initialize(@maximum_streams, @bidirectional); end
    def type : FrameType; FrameType::STREAMS_BLOCKED; end
    def encode(io : IO)
      VarInt.write(io, @bidirectional ? 0x16_u64 : 0x17_u64)
      VarInt.write(io, @maximum_streams)
    end
  end


  class PathChallengeFrame < Frame
    getter data : Bytes
    def initialize(@data)
      raise ArgumentError.new("PathChallenge data must be 8 bytes") if @data.size != 8
    end
    def type : FrameType; FrameType::PATH_CHALLENGE; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      io.write @data
    end
  end

  class PathResponseFrame < Frame
    getter data : Bytes
    def initialize(@data)
      raise ArgumentError.new("PathResponse data must be 8 bytes") if @data.size != 8
    end
    def type : FrameType; FrameType::PATH_RESPONSE; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      io.write @data
    end
  end

  class NewConnectionIdFrame < Frame
    getter sequence_number : UInt64
    getter retire_prior_to : UInt64
    getter connection_id : Bytes
    getter stateless_reset_token : Bytes

    def initialize(@sequence_number, @retire_prior_to, @connection_id, @stateless_reset_token)
    end

    def type : FrameType; FrameType::NEW_CONNECTION_ID; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @sequence_number)
      VarInt.write(io, @retire_prior_to)
      io.write_byte @connection_id.size.to_u8
      io.write @connection_id
      io.write @stateless_reset_token
    end
  end

  class RetireConnectionIdFrame < Frame
    getter sequence_number : UInt64
    def initialize(@sequence_number); end
    def type : FrameType; FrameType::RETIRE_CONNECTION_ID; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @sequence_number)
    end
  end

  class HandshakeDoneFrame < Frame
    def type : FrameType; FrameType::HANDSHAKE_DONE; end
    def encode(io : IO); VarInt.write(io, type.to_u64); end
  end

  class DatagramFrame < Frame
    getter data : Bytes
    def initialize(@data); end
    def type : FrameType; FrameType::DATAGRAM; end
    def encode(io : IO)
      # We use the variant with length for simplicity (0x31)
      VarInt.write(io, 0x31_u64)
      VarInt.write(io, @data.size.to_u64)
      io.write @data
    end
  end

  class ConnectionCloseFrame < Frame
    getter error_code : UInt64
    getter frame_type : UInt64
    getter reason : String
    def initialize(@error_code, @frame_type, @reason); end
    def type : FrameType; FrameType::CONNECTION_CLOSE; end
    def encode(io : IO)
      VarInt.write(io, type.to_u64)
      VarInt.write(io, @error_code)
      VarInt.write(io, @frame_type)
      VarInt.write(io, @reason.bytesize.to_u64)
      io.write @reason.to_slice
    end
  end
end
