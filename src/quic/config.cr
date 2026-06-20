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
    
    property cert_file : String = "cert.pem"
    property key_file : String = "key.pem"
    
    def initialize
    end
  end
end
