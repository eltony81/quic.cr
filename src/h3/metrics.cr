module H3
  module Metrics
    @@active_connections = Atomic(Int32).new(0)
    @@total_connections  = Atomic(Int64).new(0)
    @@requests_total     = Atomic(Int64).new(0)
    @@bytes_rx           = Atomic(Int64).new(0)
    @@bytes_tx           = Atomic(Int64).new(0)
    @@packets_rx         = Atomic(Int64).new(0)
    @@packets_tx         = Atomic(Int64).new(0)

    def self.conn_open  ; @@active_connections.add(1); @@total_connections.add(1); end
    def self.conn_close ; @@active_connections.sub(1);                             end
    def self.request    ; @@requests_total.add(1);                                 end
    def self.bytes_rx(n : Int)  ; @@bytes_rx.add(n.to_i64);                       end
    def self.bytes_tx(n : Int)  ; @@bytes_tx.add(n.to_i64);                       end
    def self.packet_rx  ; @@packets_rx.add(1);                                     end
    def self.packet_tx  ; @@packets_tx.add(1);                                     end

    def self.prometheus_text : String
      String.build do |s|
        s << "# HELP h3_active_connections Current open QUIC connections\n"
        s << "# TYPE h3_active_connections gauge\n"
        s << "h3_active_connections #{@@active_connections.get}\n\n"
        s << "# HELP h3_connections_total Total QUIC connections accepted\n"
        s << "# TYPE h3_connections_total counter\n"
        s << "h3_connections_total #{@@total_connections.get}\n\n"
        s << "# HELP h3_requests_total Total HTTP/3 requests handled\n"
        s << "# TYPE h3_requests_total counter\n"
        s << "h3_requests_total #{@@requests_total.get}\n\n"
        s << "# HELP h3_bytes_received_total Total bytes received from clients\n"
        s << "# TYPE h3_bytes_received_total counter\n"
        s << "h3_bytes_received_total #{@@bytes_rx.get}\n\n"
        s << "# HELP h3_bytes_sent_total Total bytes sent to clients\n"
        s << "# TYPE h3_bytes_sent_total counter\n"
        s << "h3_bytes_sent_total #{@@bytes_tx.get}\n\n"
        s << "# HELP h3_packets_received_total Total UDP packets received\n"
        s << "# TYPE h3_packets_received_total counter\n"
        s << "h3_packets_received_total #{@@packets_rx.get}\n\n"
        s << "# HELP h3_packets_sent_total Total UDP packets sent\n"
        s << "# TYPE h3_packets_sent_total counter\n"
        s << "h3_packets_sent_total #{@@packets_tx.get}\n"
      end
    end
  end
end
