module QUIC
  class Config
    property max_idle_timeout : UInt64 = 30_000 # ms
    property max_udp_payload_size : UInt64 = 1200
    property initial_max_data : UInt64 = 0
    property initial_max_stream_data_bidi_local : UInt64 = 0
    property initial_max_stream_data_bidi_remote : UInt64 = 0
    property initial_max_stream_data_uni : UInt64 = 0
    property initial_max_streams_bidi : UInt64 = 0
    property initial_max_streams_uni : UInt64 = 0
    property ack_delay_exponent : UInt64 = 3
    property max_ack_delay : UInt64 = 25
    property max_datagram_frame_size : UInt64 = 0

    # Initial congestion window in MTU-sized packets (RFC 9002 §7.2).
    # Default 32 is more aggressive than the RFC minimum of 10 but safe for
    # modern server workloads; increase further for known-good LAN paths.
    property initial_cwnd_packets : UInt32 = 32_u32

    property cert_file : String = "cert.pem"
    property key_file : String = "key.pem"

    # Optional TLS session ticket for 0-RTT resumption.
    # Set on the client before creating the connection to trigger early-data mode.
    property session_ticket : Bytes? = nil

    def initialize
    end
  end
end
