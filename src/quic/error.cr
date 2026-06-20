module QUIC
  # Error Codes (RFC 9000 Section 20.1)
  module ErrorCode
    NO_ERROR = 0x0_u64
    INTERNAL_ERROR = 0x1_u64
    CONNECTION_REFUSED = 0x2_u64
    FLOW_CONTROL_ERROR = 0x3_u64
    STREAM_LIMIT_ERROR = 0x4_u64
    STREAM_STATE_ERROR = 0x5_u64
    FINAL_SIZE_ERROR = 0x6_u64
    FRAME_ENCODING_ERROR = 0x7_u64
    TRANSPORT_PARAMETER_ERROR = 0x8_u64
    CONNECTION_ID_LIMIT_ERROR = 0x9_u64
    PROTOCOL_VIOLATION = 0xA_u64
    INVALID_TOKEN = 0xB_u64
    APPLICATION_ERROR = 0xC_u64
    CRYPTO_BUFFER_EXCEEDED = 0xD_u64
    KEY_UPDATE_ERROR = 0xE_u64
    AEAD_LIMIT_REACHED = 0xF_u64
    NO_VIABLE_PATH = 0x10_u64
    CRYPTO_ERROR_BASE = 0x0100_u64
  end

  class Error < Exception
    def error_code : UInt64
      ErrorCode::INTERNAL_ERROR
    end
  end

  # Protocol errors (RFC 9000 Section 20)
  class InternalError < Error; end
  class ProtocolViolation < Error
    def error_code : UInt64; ErrorCode::PROTOCOL_VIOLATION; end
  end
  class InvalidPacket < Error
    def error_code : UInt64; ErrorCode::PROTOCOL_VIOLATION; end
  end
  class BufferTooShort < Error
    def error_code : UInt64; ErrorCode::FRAME_ENCODING_ERROR; end
  end
  class Done < Error; end # Special error indicating no more data to send/recv (like quiche)
end
