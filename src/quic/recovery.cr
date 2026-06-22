module QUIC
  class Recovery
    # Per-space largest-acked (0=Initial, 1=Handshake, 2=App)
    @largest_acked = {0 => 0_u64, 1 => 0_u64, 2 => 0_u64}
    @pending_loss_detection : Bool = false

    def pending_loss_detection?; @pending_loss_detection; end
    def clear_pending_loss_detection; @pending_loss_detection = false; end
    def largest_acked; @largest_acked; end
    # Key: {space_id, packet_number} — avoids collisions between Initial/Handshake/App
    # spaces that each independently start their packet numbers at 0.
    @sent_packets = {} of {Int32, UInt64} => SentPacket
    
    # RTT Estimation (RFC 9002 Section 5.3)
    property latest_rtt : Time::Span = 333.milliseconds
    property smoothed_rtt : Time::Span = 333.milliseconds
    property rttvar : Time::Span = 166.milliseconds
    property min_rtt : Time::Span = Time::Span::MAX

    # Congestion Control (RFC 9002 NewReno)
    MAX_DATAGRAM_SIZE = 1472_u64
    INITIAL_WINDOW = 32_u64 * MAX_DATAGRAM_SIZE
    MIN_WINDOW = 2_u64 * MAX_DATAGRAM_SIZE
    LOSS_REDUCTION_FACTOR = 0.5

    @congestion_window : UInt64
    @bytes_in_flight : UInt64 = 0
    @ssthresh : UInt64 = UInt64::MAX
    @congestion_recovery_start_time : Time? = nil

    # BBR variables
    property? bbr_enabled : Bool = false
    getter bbr_min_rtt : Time::Span = Time::Span::MAX
    getter bbr_max_bandwidth : Float64 = 0.0 # bytes per second
    @bbr_delivered : UInt64 = 0
    @bbr_delivered_time : Time = Time.local

    # PTO (RFC 9002 Section 6.2)
    @pto_count : Int32 = 0

    # ECN / persistent congestion tracking (RFC 9002 §7.6)
    @last_ecn_ce : UInt64 = 0_u64
    @oldest_loss_time : Time? = nil

    def initialize(initial_window : UInt64 = INITIAL_WINDOW)
      @congestion_window = initial_window
    end

    class SentPacket
      property packet_number : UInt64
      property time_sent : Time
      property bytes : UInt32
      property ack_eliciting : Bool
      property delivered : UInt64 = 0
      property delivered_time : Time = Time.local
      property frames : Array(Frame) = [] of Frame

      def initialize(@packet_number, @time_sent, @bytes, @ack_eliciting = true)
      end
    end

    def on_packet_sent(pn : UInt64, bytes : Int, frames : Array(Frame) = [] of Frame, ack_eliciting : Bool = true, space_id : Int32 = 2)
      # RFC 9002 §7.5: non-ack-eliciting packets (ACK-only) are not counted
      # as inflight and need not be tracked — they are never ACKed back by the peer,
      # so including them in bytes_in_flight permanently inflates the counter.
      return unless ack_eliciting
      packet = SentPacket.new(pn, Time.local, bytes.to_u32, ack_eliciting)
      packet.frames = frames
      packet.delivered = @bbr_delivered
      packet.delivered_time = @bbr_delivered_time
      @sent_packets[{space_id, pn}] = packet
      @bytes_in_flight += bytes
    end

    def on_ack_received(ack : AckFrame, time_received : Time = Time.local, space_id : Int32 = 2)
      # 1. Update RTT
      if packet = @sent_packets[{space_id, ack.largest_acknowledged}]?
        update_rtt(time_received - packet.time_sent, ack.ack_delay.milliseconds)
      end

      # 2. Mark acknowledged packets — first range
      smallest = ack.largest_acknowledged > ack.first_ack_range ? ack.largest_acknowledged - ack.first_ack_range : 0_u64
      ack_range(smallest, ack.largest_acknowledged, time_received, space_id)

      # Additional ACK ranges (RFC 9000 Section 19.3.1)
      ack.ack_ranges.each do |(gap, ack_len)|
        # The next range's largest is gap+2 below the previous range's smallest
        next_largest = smallest > (gap + 2) ? smallest - gap - 2 : 0_u64
        next_smallest = next_largest > ack_len ? next_largest - ack_len : 0_u64
        ack_range(next_smallest, next_largest, time_received, space_id)
        smallest = next_smallest
      end

      @largest_acked[space_id] = Math.max(@largest_acked[space_id]? || 0_u64, ack.largest_acknowledged)
      @pto_count = 0 # Reset PTO on successful ACK
      @pending_loss_detection = true

      # ECN-CE congestion signal (RFC 9002 §7.6): new CE marks → congestion event.
      if ack.has_ecn? && ack.ecn_ce > @last_ecn_ce
        @last_ecn_ce = ack.ecn_ce
        @congestion_recovery_start_time = Time.local
        @ssthresh = Math.max((@congestion_window.to_f * LOSS_REDUCTION_FACTOR).to_u64, MIN_WINDOW)
        @congestion_window = @ssthresh
        Log.info { "ECN-CE congestion signal: cwnd reduced to #{@congestion_window}" }
      end
    end

    private def ack_range(from_pn : UInt64, to_pn : UInt64, time_received : Time, space_id : Int32 = 2)
      (from_pn..to_pn).each do |pn|
        if packet = @sent_packets.delete({space_id, pn})
          @bytes_in_flight -= packet.bytes if @bytes_in_flight >= packet.bytes

          @bbr_delivered += packet.bytes
          @bbr_delivered_time = time_received

          rtt = time_received - packet.time_sent
          @bbr_min_rtt = Math.min(@bbr_min_rtt, rtt)

          delivery_interval = time_received - packet.delivered_time
          if delivery_interval > Time::Span.zero
            delivered_diff = @bbr_delivered - packet.delivered
            rate = delivered_diff.to_f / delivery_interval.to_f
            @bbr_max_bandwidth = Math.max(@bbr_max_bandwidth, rate)
          end

          if @bbr_enabled
            if @bbr_min_rtt != Time::Span::MAX && @bbr_max_bandwidth > 0.0
              bdp = @bbr_max_bandwidth * @bbr_min_rtt.to_f
              @congestion_window = Math.max(5888_u64, (2.0 * bdp).to_u64)
            end
          else
            if @congestion_recovery_start_time.nil? || packet.time_sent > @congestion_recovery_start_time.not_nil!
              if @congestion_window < @ssthresh
                @congestion_window += packet.bytes
              else
                @congestion_window += (MAX_DATAGRAM_SIZE * packet.bytes) // @congestion_window
              end
            end
          end
        end
      end
    end

    private def update_rtt(latest_rtt : Time::Span, ack_delay : Time::Span)
      @latest_rtt = latest_rtt
      @min_rtt = Math.min(@min_rtt, latest_rtt)
      
      # Adjusted RTT (RFC 9002 Section 5.3.1)
      adjusted_rtt = latest_rtt
      if latest_rtt > @min_rtt + ack_delay
        adjusted_rtt = latest_rtt - ack_delay
      end

      if @smoothed_rtt == 333.milliseconds # Initial value
        @smoothed_rtt = latest_rtt
        @rttvar = latest_rtt / 2
      else
        @rttvar = (@rttvar * 0.75) + ((@smoothed_rtt - adjusted_rtt).abs * 0.25)
        @smoothed_rtt = (@smoothed_rtt * 0.875) + (adjusted_rtt * 0.125)
      end
    end

    def detect_lost_packets(largest_acked : UInt64, now : Time = Time.local, space_id : Int32 = 2) : Array(SentPacket)
      lost_packets = [] of SentPacket

      # Time-threshold only (RFC 9002 §6.1.2); packet-threshold omitted per §6.1.1 MAY
      # to avoid false positives when partial ACKs arrive before the full burst is ACKed.
      loss_delay = Math.max(@latest_rtt, @smoothed_rtt)
      loss_delay += (loss_delay / 8)
      loss_delay = Math.max(loss_delay, 1.millisecond)

      lost_keys = [] of {Int32, UInt64}
      @sent_packets.each do |(sp, pn), packet|
        next if sp != space_id
        next if pn > largest_acked

        time_since_sent = now - packet.time_sent

        if time_since_sent > loss_delay
          lost_packets << packet
          lost_keys << {sp, pn}
        end
      end

      largest_lost_time = nil

      lost_keys.each do |(sp, pn)|
        if packet = @sent_packets.delete({sp, pn})
          @bytes_in_flight -= packet.bytes if @bytes_in_flight >= packet.bytes
          
          if largest_lost_time.nil? || packet.time_sent > largest_lost_time.not_nil!
            largest_lost_time = packet.time_sent
          end
        end
      end

      # Congestion Control: Punish window on loss event
      if largest_lost_time
        if @congestion_recovery_start_time.nil? || largest_lost_time.not_nil! > @congestion_recovery_start_time.not_nil!
          @congestion_recovery_start_time = Time.local
          @ssthresh = Math.max((@congestion_window.to_f * LOSS_REDUCTION_FACTOR).to_u64, MIN_WINDOW)
          @congestion_window = @ssthresh
          Log.info { "Congestion Recovery triggered: cwnd reduced to #{@congestion_window} bytes" }
        end

        # Persistent congestion (RFC 9002 §7.6): if the span of consecutive
        # lost ack-eliciting packets exceeds 3 × PTO, collapse to minimum window.
        if !lost_packets.empty?
          oldest = lost_packets.min_by(&.time_sent).time_sent
          newest = lost_packets.max_by(&.time_sent).time_sent
          loss_span = newest - oldest
          persistent_threshold = pto_timeout * 3
          if loss_span >= persistent_threshold
            @congestion_window = MIN_WINDOW
            @ssthresh = MIN_WINDOW
            @oldest_loss_time = nil
            Log.info { "Persistent congestion detected: cwnd collapsed to #{MIN_WINDOW}" }
          end
        end
      end

      lost_packets
    end

    def pto_timeout : Time::Span
      base = @smoothed_rtt + (@rttvar * 4) + 25.milliseconds
      # 100ms floor prevents premature PTO during TLS handshake (~50ms crypto).
      # Exponential backoff per RFC 9002 §6.2.1 (2^pto_count, capped at 8×).
      effective = base > 100.milliseconds ? base : 100.milliseconds
      effective * Math.min(1 << @pto_count, 8)
    end

    def timeout : Time?
      return nil if @sent_packets.empty?
      oldest_packet = @sent_packets.values.min_by(&.time_sent)
      oldest_packet.time_sent + pto_timeout
    end

    def on_pto_timeout : Array(SentPacket)
      @pto_count += 1
      lost_packets = @sent_packets.values.to_a
      @sent_packets.clear
      @bytes_in_flight = 0
      lost_packets
    end

    def bytes_in_flight
      @bytes_in_flight
    end

    def congestion_window
      @congestion_window
    end

    def pto_count
      @pto_count
    end

    def sent_packet_count
      @sent_packets.size
    end

    def can_send? : Bool
      @bytes_in_flight < @congestion_window
    end

    # Estimated pacing rate in bytes/second for SO_TXTIME kernel scheduling.
    # Uses BBR max-bandwidth when available; falls back to cwnd/RTT (NewReno).
    def pacing_rate_bps : Float64
      if @bbr_enabled && @bbr_max_bandwidth > 0.0
        @bbr_max_bandwidth * 1.25 # BBR startup pacing gain
      elsif @smoothed_rtt > Time::Span.zero
        @congestion_window.to_f / @smoothed_rtt.total_seconds
      else
        12_500_000.0 # default 100 Mbps until first RTT sample
      end
    end
  end
end
