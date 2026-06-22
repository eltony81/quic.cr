module H3
  # HTTP/3 application-level error codes (RFC 9114 §8.1).
  # These are used as the application error code in QUIC RESET_STREAM /
  # STOP_SENDING / CONNECTION_CLOSE frames.
  module ErrorCode
    H3_NO_ERROR               = 0x0100_u64
    H3_GENERAL_PROTOCOL_ERROR = 0x0101_u64
    H3_INTERNAL_ERROR         = 0x0102_u64
    H3_STREAM_CREATION_ERROR  = 0x0103_u64
    H3_CLOSED_CRITICAL_STREAM = 0x0104_u64
    H3_FRAME_UNEXPECTED       = 0x0105_u64
    H3_FRAME_ERROR            = 0x0106_u64
    H3_EXCESSIVE_LOAD         = 0x0107_u64
    H3_ID_ERROR               = 0x0108_u64
    H3_SETTINGS_ERROR         = 0x0109_u64
    H3_MISSING_SETTINGS       = 0x010a_u64
    H3_REQUEST_REJECTED       = 0x010b_u64
    H3_REQUEST_CANCELLED      = 0x010c_u64
    H3_REQUEST_INCOMPLETE     = 0x010d_u64
    H3_MESSAGE_ERROR          = 0x010e_u64
    H3_CONNECT_ERROR          = 0x010f_u64
    H3_VERSION_FALLBACK       = 0x0110_u64
  end
end
