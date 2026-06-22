module QUIC
  class PacketNumberSpace
    property largest_acked : UInt64 = 0
    property packet_number : UInt64 = 0
    property received_pns = [] of UInt64
    property pending_ack : Bool = false
    property aead_rx : Crypto::AEAD?
    property aead_tx : Crypto::AEAD?
    property hp_rx : Crypto::HeaderProtection?
    property hp_tx : Crypto::HeaderProtection?
  end

  class Path
    property id : UInt64
    property local_address : Socket::IPAddress?
    property remote_address : Socket::IPAddress?
    property recovery : Recovery
    property? validated : Bool = false
    property bytes_sent : UInt64 = 0
    property bytes_received : UInt64 = 0

    def initialize(@id, initial_cwnd : UInt64 = Recovery::INITIAL_WINDOW, @local_address = nil, @remote_address = nil)
      @recovery = Recovery.new(initial_cwnd)
      @validated = true if @id == 0
    end
  end

  class Connection
    @config : Config
    getter? is_server : Bool
    @tls : TLS
    getter dcid : Bytes?
    getter scid : Bytes?
    
    @space_initial : PacketNumberSpace = PacketNumberSpace.new
    @space_handshake : PacketNumberSpace = PacketNumberSpace.new
    @space_zero_rtt : PacketNumberSpace = PacketNumberSpace.new  # 0-RTT early data
    @space_app : PacketNumberSpace = PacketNumberSpace.new

    getter streams = {} of UInt64 => Stream
    
    @crypto_bufs = {} of PacketNumberSpace => Hash(UInt64, Bytes)
    @crypto_rx_offsets = {} of PacketNumberSpace => UInt64
    @crypto_tx_offsets = {} of PacketNumberSpace => UInt64
    
    @lost_frames = [] of Frame
    
    getter paths : Array(Path) = [] of Path
    getter active_path_id : UInt64 = 0
    getter recovery : Recovery
    
    @max_data_local : UInt64
    @max_data_remote : UInt64 = 0_u64
    @data_sent : UInt64 = 0_u64
    @pending_data_blocked : Bool = false
    @pending_stream_data_blocked = [] of UInt64
    @pending_max_data : Bool = false
    @pending_max_stream_data = [] of UInt64
    @data_received : UInt64 = 0
    
    @closed : Bool = false
    @close_sent : Bool = false
    @close_error : UInt64 = 0
    @close_reason : String = ""

    # RESET_STREAM frames to emit on next send (stream_id, error_code, final_size).
    @pending_reset_streams = [] of {UInt64, UInt64, UInt64}

    # Outbound max-stream limits received from the peer (updated by MAX_STREAMS frames).
    getter max_streams_bidi_remote : UInt64 = 0_u64
    getter max_streams_uni_remote  : UInt64 = 0_u64

    # Inbound stream grant we have issued to the peer (RFC 9000 §4.6).
    # Replenished dynamically: when the peer has consumed ≥50% of the current limit,
    # we raise it by initial_max_streams_bidi and queue a MAX_STREAMS frame.
    @max_streams_bidi_local   : UInt64 = 128_u64  # overwritten in initialize from config
    @peer_streams_bidi_opened : UInt64 = 0_u64    # highest peer-initiated bidi ordinal seen
    @pending_max_streams_bidi : UInt64 = 0_u64    # >0 → emit MAX_STREAMS on next send

    # Server queues one HANDSHAKE_DONE frame immediately after handshake completes.
    @pending_handshake_done : Bool = false
    @handshake_notified     : Bool = false
    
    # Event notification channels to avoid sleep polling
    getter handshake_chan : Channel(Bool) = Channel(Bool).new(1)
    getter stream_chans : Hash(UInt64, Channel(Bool)) = {} of UInt64 => Channel(Bool)
    
    def handshake_complete? : Bool
      @tls.handshake_complete?
    end

    # Returns serialized TLS session bytes for 0-RTT resumption on the next connection.
    # Available after the server has sent a NewSessionTicket (typically after the first
    # response is received). Returns nil if the session is not yet available.
    def session_bytes : Bytes?
      @tls.session_bytes
    end

    # Returns true if the current connection resumed a saved TLS session (0-RTT mode).
    def session_resumed? : Bool
      @tls.session_resumed?
    end

    @pending_path_responses = [] of Bytes
    @pending_path_challenges = [] of Bytes     # queued to send as PATH_CHALLENGE
    @outstanding_path_challenges = Set(String).new  # sent, awaiting PATH_RESPONSE
    getter? path_validated : Bool = false

    property? version_negotiation_failed : Bool = false
    @retry_token : Bytes = Bytes.empty
    
    @queued_datagrams : Array(Bytes) = [] of Bytes
    property on_datagram : Proc(Bytes, Nil)?

    property path_mtu : UInt64 = 1200
    @pmtud_probe_size : UInt64 = 1200
    @pmtud_probe_pn : UInt64? = nil
    @pmtud_probe_sent_size : UInt64 = 0

    @client_handshake_secret : Bytes?
    @server_handshake_secret : Bytes?
    @client_app_secret : Bytes?
    @server_app_secret : Bytes?

    @client_handshake_seq_num = 0_u64
    @server_handshake_seq_num = 0_u64
    @client_app_seq_num = 0_u64
    @server_app_seq_num = 0_u64

    @original_destination_connection_id : Bytes? = nil
    @initial_source_connection_id : Bytes? = nil
    getter initial_dcid : Bytes? = nil

    @client_finished_sent = false
    @server_finished_sent = false
    
    @pending_initial_tls : Bytes? = nil
    @pending_handshake_tls : Bytes? = nil
    @remote_tp_applied : Bool = false

    @initial_handshake_bytes = IO::Memory.new
    @handshake_handshake_bytes = IO::Memory.new
    # Pre-allocated send buffers — reused every call to avoid GC pressure in send().
    @send_payload_io = IO::Memory.new(2048)
    @send_header_io  = IO::Memory.new(256)
    @send_ad_io      = IO::Memory.new(256)
    @dcid_locked = false

    def initialize(@config : Config, @is_server : Bool)
      @crypto_bufs[@space_initial] = {} of UInt64 => Bytes
      @crypto_bufs[@space_handshake] = {} of UInt64 => Bytes
      @crypto_bufs[@space_app] = {} of UInt64 => Bytes
      
      @crypto_rx_offsets[@space_initial] = 0_u64
      @crypto_rx_offsets[@space_handshake] = 0_u64
      @crypto_rx_offsets[@space_app] = 0_u64
      
      @crypto_tx_offsets[@space_initial] = 0_u64
      @crypto_tx_offsets[@space_handshake] = 0_u64
      @crypto_tx_offsets[@space_app] = 0_u64

      initial_cwnd = @config.initial_cwnd_packets.to_u64 * Recovery::MAX_DATAGRAM_SIZE
      @paths << Path.new(0, initial_cwnd)
      @recovery = @paths[0].recovery

      unless @is_server
        @dcid = Random::Secure.random_bytes(8)
        @initial_dcid = @dcid  # saved for Retry integrity tag verification (RFC 9001 §5.8)
        @scid = Random::Secure.random_bytes(8)
        setup_initial_secrets(@dcid.not_nil!)
      end

      @tls = TLS.new(@config, @is_server, @scid)
      @tls.on_secret = ->(label : String, secret : Bytes) {
        handle_secret(label, secret)
      }
      @max_data_local = @config.initial_max_data
      @max_streams_bidi_local = @config.initial_max_streams_bidi
      unless @is_server
        # Populate transport parameters for the client
        tp = TransportParameters.new
        tp.max_idle_timeout = @config.max_idle_timeout
        tp.initial_max_data = @config.initial_max_data
        tp.initial_max_stream_data_bidi_local = @config.initial_max_stream_data_bidi_local
        tp.initial_max_stream_data_bidi_remote = @config.initial_max_stream_data_bidi_remote
        tp.initial_max_stream_data_uni = @config.initial_max_stream_data_uni
        tp.initial_max_streams_bidi = @config.initial_max_streams_bidi
        tp.initial_max_streams_uni = @config.initial_max_streams_uni
        tp.initial_source_connection_id = @scid
        @tls.update_local_tp(tp)
      end
    end

    def tick(now : Time = Time.local)
      if timeout = @recovery.timeout
        if now >= timeout
          Log.trace { "PTO EXPIRED! Requeuing unacknowledged packets." }
          lost_pkts = @recovery.on_pto_timeout
          lost_pkts.each do |pkt|
            pkt.frames.each do |f|
              if f.is_a?(StreamFrame) || f.is_a?(CryptoFrame) || f.is_a?(MaxDataFrame) || f.is_a?(MaxStreamDataFrame) || f.is_a?(DatagramFrame)
                @lost_frames << f
              end
            end
          end
        end
      end
    end

    def recv(data : Bytes) : Int32
      return 0 if @closed

      begin
        # Stateless Reset Check (RFC 9000 Section 10.3)
        if !@is_server && data.size >= 37
          token = data[-16..-1]
          if (tp = @tls.remote_transport_parameters) && (expected = tp.stateless_reset_token) && Crypto.constant_time_compare(token, expected)
            @closed = true
            @close_error = 0x14_u64
            return data.size
          end
        end

        active_path.bytes_received += data.size.to_u64

        # RFC 9000 §12.2: a UDP datagram may contain multiple coalesced QUIC
        # packets (long-header first, short-header last). Process all of them.
        offset = 0
        while offset < data.size
          pkt = data[offset..].dup
          consumed = recv_packet(pkt)
          break if consumed <= 0
          offset += consumed
        end

        data.size
      rescue e : QUIC::Error
        Log.error { "QUIC Protocol Error: #{e.class} - #{e.message}" }
        @closed = true
        @close_error = e.error_code
        @close_reason = e.message || "Protocol Error"
        0
      rescue e : Exception
        Log.error { "QUIC Internal Error: #{e.class} - #{e.message}" }
        @closed = true
        @close_error = QUIC::ErrorCode::INTERNAL_ERROR
        @close_reason = "Internal Error"
        0
      end
    end

    # Processes exactly one QUIC packet from `data` and returns the number of
    # bytes consumed (0 on failure).  Called in a loop by recv() to handle
    # coalesced datagrams (RFC 9000 §12.2).
    private def recv_packet(data : Bytes) : Int32
      final_data = data
      io = IO::Memory.new(final_data)

      first_byte = io.read_byte || return 0
      is_long = (first_byte & 0x80) != 0

      if is_long
        version = IO::ByteFormat::NetworkEndian.decode(UInt32, io)
        Log.trace { "RECV DEBUG: long header version=#{version.to_s(16)} first_byte=#{first_byte.to_s(16)}" }
        dcid_len = io.read_byte || return 0
        dcid = Bytes.new(dcid_len)
        io.read_fully(dcid)

        setup_initial_secrets(dcid) unless @space_initial.aead_rx

        scid_len = io.read_byte || return 0
        scid = Bytes.new(scid_len)
        io.read_fully(scid)

        if !@is_server && !@dcid_locked
          @dcid = scid
          @dcid_locked = true
        end

        if !@is_server && version == 0x00000000_u32
          @version_negotiation_failed = true
          @closed = true
          return data.size
        end

        if @is_server && @dcid.nil?
          @dcid = scid
          @scid = Random::Secure.random_bytes(8)
          @original_destination_connection_id = dcid
          @initial_source_connection_id = @scid

          tp = TransportParameters.new
          tp.max_idle_timeout = @config.max_idle_timeout
          tp.initial_max_data = @config.initial_max_data
          tp.initial_max_stream_data_bidi_local = @config.initial_max_stream_data_bidi_local
          tp.initial_max_stream_data_bidi_remote = @config.initial_max_stream_data_bidi_remote
          tp.initial_max_stream_data_uni = @config.initial_max_stream_data_uni
          tp.initial_max_streams_bidi = @config.initial_max_streams_bidi
          tp.initial_max_streams_uni = @config.initial_max_streams_uni
          tp.original_destination_connection_id = dcid
          tp.initial_source_connection_id = @scid.not_nil!
          @tls.update_local_tp(tp)
        end

        type_bits = (first_byte >> 4) & 0x03

        if !@is_server && type_bits == 0x03
          # Retry packet
          token_len = io.size - io.pos - 16
          if token_len >= 0
            token = Bytes.new(token_len)
            io.read_fully(token)
            tag = Bytes.new(16)
            io.read_fully(tag)

            # Verify Retry Integrity Tag (RFC 9001 Section 5.8).
            # The tag is AES-128-GCM over the pseudo-Retry packet whose AAD
            # includes the ODCID — the DCID we chose for our very first Initial.
            if odcid = @initial_dcid
              unless AddressValidation.verify_retry_integrity(odcid, final_data)
                Log.warn { "Retry packet integrity tag verification failed, ignoring" }
                return data.size
              end
            end

            @retry_token = token
            @dcid = scid
            @space_initial = PacketNumberSpace.new
            setup_initial_secrets(scid)

            # Re-initialize TLS to regenerate ClientHello
            @tls = TLS.new(@config, @is_server)
            @tls.on_secret = ->(label : String, secret : Bytes) {
              handle_secret(label, secret)
            }
          end
          return data.size
        end

        space = case type_bits
                when 0x00 then @space_initial    # Initial
                when 0x01 then @space_zero_rtt   # 0-RTT Protected (RFC 9000 §17.2.3)
                when 0x02 then @space_handshake  # Handshake
                else @space_initial
                end

        token_len = 0_u64
        if type_bits == 0x00 # Initial
          token_len = VarInt.decode(io)
          io.skip(token_len)
        end

        length_val = VarInt.decode(io)
        pn_offset = io.pos.to_i

        Log.trace { "RECV DEBUG: type_bits=#{type_bits} token_len=#{token_len} length_val=#{length_val} pn_offset=#{pn_offset} final_data_size=#{final_data.size}" }

        return data.size unless space.hp_rx

        sample_offset = pn_offset + 4
        Log.trace { "RECV DEBUG: sample_offset=#{sample_offset} space_has_hp_rx=#{!space.hp_rx.nil?}" }
        sample = final_data[sample_offset .. sample_offset + 15]
        mask = space.hp_rx.not_nil!.mask(sample)
        Log.trace { "RECV DEBUG: mask=#{mask.hexstring} first_byte_before=#{final_data[0].to_s(16)}" }
        space.hp_rx.not_nil!.apply!(final_data, pn_offset, mask, unprotect: true)
        Log.trace { "RECV DEBUG: first_byte_after=#{final_data[0].to_s(16)}" }

        pn_len = (final_data[0] & 0x03) + 1
        packet_end = pn_offset + length_val
        ad = final_data[0...pn_offset + pn_len]
        ciphertext = final_data[pn_offset + pn_len ... packet_end]

        pn_io = IO::Memory.new(final_data[pn_offset, pn_len])
        pn = case pn_len
             when 1 then pn_io.read_byte.not_nil!.to_u64
             when 2 then IO::ByteFormat::NetworkEndian.decode(UInt16, pn_io).to_u64
             when 3
               b = Bytes.new(3)
               pn_io.read_fully(b)
               (b[0].to_u64 << 16) | (b[1].to_u64 << 8) | b[2].to_u64
             when 4 then IO::ByteFormat::NetworkEndian.decode(UInt32, pn_io).to_u64
             else 0_u64
             end

        Log.trace { "RECV DEBUG: pn=#{pn} pn_len=#{pn_len} ciphertext_size=#{ciphertext.size} ad=#{ad.hexstring}" }
        aead = space.aead_rx
        return data.size unless aead
        plaintext = aead.decrypt(ad, pn, ciphertext)

        space.received_pns << pn

        has_ack_eliciting = false
        payload_io = IO::Memory.new(plaintext)
        while payload_io.pos < payload_io.size
          frame = Frame.decode(payload_io)
          unless frame.is_a?(AckFrame) || frame.is_a?(ConnectionCloseFrame) || frame.is_a?(PaddingFrame)
            has_ack_eliciting = true
          end
          handle_frame(frame, space)
        end
        space.pending_ack = true if has_ack_eliciting

        # Return bytes consumed by this long-header packet so recv() can advance
        # to the next coalesced packet (short-header is always last, per RFC).
        packet_end.to_i
      else
        # Short Header — always the last packet in a coalesced datagram.
        dcid = Bytes.new(8)
        io.read_fully(dcid)
        pn_offset = io.pos.to_i

        return 0 unless @space_app.hp_rx

        sample_offset = pn_offset + 4
        sample = final_data[sample_offset .. sample_offset + 15]
        mask = @space_app.hp_rx.not_nil!.mask(sample)
        @space_app.hp_rx.not_nil!.apply!(final_data, pn_offset, mask, unprotect: true)

        pn_len = (final_data[0] & 0x03) + 1
        ad = final_data[0...pn_offset + pn_len]
        ciphertext = final_data[pn_offset + pn_len .. -1]

        pn_io = IO::Memory.new(final_data[pn_offset, pn_len])
        pn = case pn_len
             when 1 then pn_io.read_byte.not_nil!.to_u64
             when 2 then IO::ByteFormat::NetworkEndian.decode(UInt16, pn_io).to_u64
             when 3
               b = Bytes.new(3)
               pn_io.read_fully(b)
               (b[0].to_u64 << 16) | (b[1].to_u64 << 8) | b[2].to_u64
             when 4 then IO::ByteFormat::NetworkEndian.decode(UInt32, pn_io).to_u64
             else 0_u64
             end

        plaintext = @space_app.aead_rx.not_nil!.decrypt(ad, pn, ciphertext)

        @space_app.received_pns << pn

        has_ack_eliciting = false
        payload_io = IO::Memory.new(plaintext)
        while payload_io.pos < payload_io.size
          frame = Frame.decode(payload_io)
          unless frame.is_a?(AckFrame) || frame.is_a?(ConnectionCloseFrame) || frame.is_a?(PaddingFrame)
            has_ack_eliciting = true
          end
          handle_frame(frame, @space_app)
        end
        @space_app.pending_ack = true if has_ack_eliciting

        # Short-header packets extend to the end of the datagram.
        data.size
      end
    end

    private def space_id(space : PacketNumberSpace) : Int32
      if space == @space_initial
        0
      elsif space == @space_handshake
        1
      else
        2
      end
    end

    private def handle_frame(frame : Frame, space : PacketNumberSpace)
      unless frame.is_a?(PaddingFrame)
        Log.trace { "RECV FRAME: #{frame.class} - #{frame.inspect}" }
      end
      case frame
      when CryptoFrame
        Log.trace { "RECV CRYPTO FRAME: offset=#{frame.offset} size=#{frame.data.size}" }
        handle_crypto_frame(frame, space)
      when StreamFrame
        is_new_peer_bidi = (frame.id % 4 == (@is_server ? 0_u64 : 1_u64)) && !@streams.has_key?(frame.id)
        stream = @streams[frame.id] ||= begin
          max_remote, max_local = initial_stream_limits(frame.id)
          Stream.new(frame.id, max_remote, max_local)
        end
        if is_new_peer_bidi
          ordinal = (frame.id >> 2) + 1_u64
          if ordinal > @peer_streams_bidi_opened
            @peer_streams_bidi_opened = ordinal
            maybe_extend_max_streams_bidi
          end
        end
        
        if @data_received + frame.data.size > @max_data_local
          close(0x01_u64, "Flow control error")
          return
        end
        @data_received += frame.data.size
        stream.receive_data(frame.offset, frame.data)
        if frame.fin
          stream.set_fin_offset(frame.offset + frame.data.size)
        end
        
        # Notify channel that stream has new data/state update
        if chan = @stream_chans[frame.id]?
          select
          when chan.send(true)
          else
          end
        end
      when AckFrame
        sid = space_id(space)
        @paths.each { |p| p.recovery.on_ack_received(frame, space_id: sid) }

        # Trigger loss detection
        lost_pkts = @recovery.detect_lost_packets(frame.largest_acknowledged, space_id: sid)
        lost_pkts.each do |pkt|
          pkt.frames.each do |f|
            # Retransmit data-bearing frames
            if f.is_a?(StreamFrame) || f.is_a?(CryptoFrame) || f.is_a?(MaxDataFrame) || f.is_a?(MaxStreamDataFrame) || f.is_a?(DatagramFrame)
              @lost_frames << f
            end
          end
        end

        if (pn = @pmtud_probe_pn) && (frame.largest_acknowledged - frame.first_ack_range .. frame.largest_acknowledged).includes?(pn)
          @path_mtu = @pmtud_probe_sent_size
          @pmtud_probe_pn = nil
        end
      when DatagramFrame
        @on_datagram.try &.call(frame.data)
      when MaxDataFrame
        @max_data_remote = Math.max(@max_data_remote, frame.maximum_data)
      when MaxStreamDataFrame
        if stream = @streams[frame.stream_id]?
          stream.update_max_stream_data(frame.maximum_stream_data)
        end
      when DataBlockedFrame
        @max_data_local += 1048576_u64 # Increase global limit by 1MB
        @pending_max_data = true
      when StreamDataBlockedFrame
        if stream = @streams[frame.stream_id]?
          # Per ora deleghiamo all'espansione automatica di 1MB
          stream.update_max_stream_data_local(stream.max_stream_data_local + 1048576_u64)
          @pending_max_stream_data << frame.stream_id
        end
      when PathChallengeFrame
        # RFC 9000 §8.2.1: echo the same 8 bytes in a PATH_RESPONSE
        @pending_path_responses << frame.data
      when PathResponseFrame
        # RFC 9000 §8.2.2: validate path if data matches an outstanding challenge
        if @outstanding_path_challenges.delete(frame.data.hexstring)
          @path_validated = true
        end
      when ResetStreamFrame
        # RFC 9000 §3.4: peer aborted its send side — unblock any waiting reader.
        stream = @streams[frame.id] ||= begin
          max_remote, max_local = initial_stream_limits(frame.id)
          Stream.new(frame.id, max_remote, max_local)
        end
        stream.reset!(frame.error_code)
        if chan = @stream_chans[frame.id]?
          select
          when chan.send(true)
          else
          end
        end
      when StopSendingFrame
        # RFC 9000 §3.5: peer wants us to stop sending — respond with RESET_STREAM.
        if stream = @streams[frame.id]?
          @pending_reset_streams << {frame.id, frame.error_code, stream.tx_offset}
          stream.close_local
        end
      when HandshakeDoneFrame
        # RFC 9001 §4.9.2: server confirmed handshake — client discards HS keys.
        discard_initial_handshake_keys unless @is_server
      when MaxStreamsFrame
        # RFC 9000 §4.6: peer raised our outbound stream limit.
        if frame.bidirectional
          @max_streams_bidi_remote = Math.max(@max_streams_bidi_remote, frame.maximum_streams)
        else
          @max_streams_uni_remote = Math.max(@max_streams_uni_remote, frame.maximum_streams)
        end
      when StreamsBlockedFrame
        # RFC 9000 §4.6: peer is about to exhaust its bidi stream quota — extend immediately.
        if frame.bidirectional
          maybe_extend_max_streams_bidi
        end
      when ConnectionCloseFrame
        Log.trace { "RECV ConnectionCloseFrame: error_code=0x#{frame.error_code.to_s(16)} reason=#{frame.reason}" }
        @closed = true
        @close_error = frame.error_code
        @close_reason = frame.reason
      end
    end

    private def handle_crypto_frame(frame : CryptoFrame, space : PacketNumberSpace)
      buf = @crypto_bufs[space]
      buf[frame.offset] = frame.data
      
      # Feed contiguous data to OpenSSL
      next_offset = @crypto_rx_offsets[space]
      
      # Gather all contiguous bytes
      contiguous_bytes = [] of Bytes
      total_size = 0
      
      while true
        found_key = buf.keys.find { |k| k <= next_offset && (val = buf[k]?) && k + val.size > next_offset }
        if found_key
          data = buf.delete(found_key)
          if data
            chunk = data[next_offset - found_key .. -1]
            if chunk.size > 0
              contiguous_bytes << chunk
              total_size += chunk.size
              next_offset += chunk.size
            end
          else
            break
          end
        else
          break
        end
      end
      
      if total_size > 0
        concatenated = Bytes.new(total_size)
        pos = 0
        contiguous_bytes.each do |cb|
          cb.copy_to(concatenated[pos, cb.size])
          pos += cb.size
        end
        
        if space == @space_initial
          @initial_handshake_bytes.write(concatenated)
          parse_transport_parameters_from_stream(@initial_handshake_bytes)
        elsif space == @space_handshake
          @handshake_handshake_bytes.write(concatenated)
          parse_transport_parameters_from_stream(@handshake_handshake_bytes)
        end

        if space == @space_initial
          @tls.handle_data(concatenated, LibSSL::OSSL_RECORD_PROTECTION_LEVEL_NONE)
        elsif space == @space_handshake
          @tls.handle_data(concatenated, LibSSL::OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE)
        else
          @tls.handle_data(concatenated, LibSSL::OSSL_RECORD_PROTECTION_LEVEL_APPLICATION)
        end
        
        # If handshake has completed, notify once and queue HANDSHAKE_DONE (server).
        if @tls.handshake_complete? && !@handshake_notified
          @handshake_notified = true
          @pending_handshake_done = true if @is_server
          select
          when @handshake_chan.send(true)
          else
          end
        end
      end
      
      @crypto_rx_offsets[space] = next_offset
    end

    def close(error_code : UInt64 = 0_u64, reason : String = "")
      return if @closed
      @closed = true
      @close_error = error_code
      @close_reason = reason
    end

    # Queue a PATH_CHALLENGE to validate a new or migrated path (RFC 9000 §8.2).
    # Returns the 8-byte challenge data; path is considered validated when we
    # receive a matching PATH_RESPONSE.
    def initiate_path_validation : Bytes
      challenge = Random::Secure.random_bytes(8)
      @pending_path_challenges << challenge
      @path_validated = false
      challenge
    end

    def send(out_buffer : Bytes) : Int32
      check_and_apply_remote_tp
      if @closed && @close_sent
        Log.trace { "SEND DEBUG: closed & close_sent" }
        return 0
      end
      unless @recovery.can_send?
        Log.trace { "SEND DEBUG: recovery blocked, bytes_in_flight=#{@recovery.bytes_in_flight} window=#{@recovery.congestion_window}" }
        return 0
      end

      # Anti-Amplification Limit (RFC 9000 Section 9.3)
      if !active_path.validated?
        limit = active_path.bytes_received * 3
        if active_path.bytes_sent + 1200 > limit
          Log.trace { "SEND DEBUG: anti-amplification limit blocked, bytes_sent=#{active_path.bytes_sent} limit=#{limit}" }
          return 0
        end
      end

      # Check if we need to poll TLS data
      if raw_initial = @tls.poll_initial
        if existing = @pending_initial_tls
          temp = Bytes.new(existing.size + raw_initial.size)
          existing.copy_to(temp[0, existing.size])
          raw_initial.copy_to(temp[existing.size, raw_initial.size])
          @pending_initial_tls = temp
        else
          @pending_initial_tls = raw_initial
        end
      end

      if raw_handshake = @tls.poll_handshake
        if existing = @pending_handshake_tls
          temp = Bytes.new(existing.size + raw_handshake.size)
          existing.copy_to(temp[0, existing.size])
          raw_handshake.copy_to(temp[existing.size, raw_handshake.size])
          @pending_handshake_tls = temp
        else
          @pending_handshake_tls = raw_handshake
        end
      end

      # Select the space and tls_data to send
      if existing = @pending_initial_tls
        space = @space_initial
        if existing.size > 1000
          tls_data = existing[0, 1000]
          @pending_initial_tls = existing[1000, existing.size - 1000]
        else
          tls_data = existing
          @pending_initial_tls = nil
        end
      elsif existing = @pending_handshake_tls
        space = @space_handshake
        if existing.size > 1000
          tls_data = existing[0, 1000]
          @pending_handshake_tls = existing[1000, existing.size - 1000]
        else
          tls_data = existing
          @pending_handshake_tls = nil
        end
      elsif @space_initial.pending_ack
        space = @space_initial
        tls_data = nil
      elsif @space_handshake.pending_ack
        space = @space_handshake
        tls_data = nil
      else
        space = if @closed && !@close_sent
                  if @space_app.aead_tx
                    @space_app
                  elsif @space_handshake.aead_tx
                    @space_handshake
                  else
                    @space_initial
                  end
                elsif @space_zero_rtt.aead_tx && !@tls.handshake_complete?
                  # 0-RTT mode: send stream data before the handshake completes
                  @space_zero_rtt
                else
                  @space_app.aead_tx ? @space_app : @space_initial
                end
        tls_data = nil
      end

      if tls_data.nil? && !space.pending_ack && !(@closed && !@close_sent) && @streams.all? { |_, s| !s.has_send_data? } && @pending_path_responses.empty? && @pending_path_challenges.empty? && @lost_frames.empty? && !@pending_handshake_done && @pending_reset_streams.empty?
        Log.trace { "SEND DEBUG: return 0 (no tls_data, no ack, no stream data, no lost frames)" }
        return 0
      end

      packet = if space == @space_app
                 return 0 if @dcid.nil?
                 ShortHeaderPacket.new(@dcid.not_nil!)
               elsif space == @space_zero_rtt
                 return 0 if @scid.nil? || @dcid.nil?
                 LongHeaderPacket.new(PacketType::ZeroRTT, 0x00000001_u32, @dcid.not_nil!, @scid.not_nil!)
               else
                 return 0 if @scid.nil? || @dcid.nil?
                 packet_type = space == @space_initial ? PacketType::Initial : PacketType::Handshake
                 LongHeaderPacket.new(
                   packet_type,
                   0x00000001_u32,
                   @dcid.not_nil!,
                   @scid.not_nil!,
                   token: @retry_token
                 )
               end
      packet.packet_number = space.packet_number

      if space == @space_app && @pmtud_probe_size > @path_mtu && @pmtud_probe_pn.nil?
        packet.frames << PingFrame.new
        payload_io = IO::Memory.new
        packet.frames.each &.encode(payload_io)
        payload_size = payload_io.to_slice.size
        
        header_io = IO::Memory.new
        packet.encode_header(header_io)
        header_size = header_io.to_slice.size
        
        current_size = header_size + 4 + payload_size + 16
        if current_size < @pmtud_probe_size
          padding_needed = @pmtud_probe_size - current_size
          padding_needed.times do
            packet.frames << PaddingFrame.new
          end
          @pmtud_probe_pn = packet.packet_number
          @pmtud_probe_sent_size = @pmtud_probe_size
        end
      end

      if @closed && !@close_sent
        packet.frames << ConnectionCloseFrame.new(@close_error, 0_u64, @close_reason)
        @close_sent = true
      end

      unless @pending_path_challenges.empty?
        @pending_path_challenges.each do |data|
          packet.frames << PathChallengeFrame.new(data)
          @outstanding_path_challenges.add(data.hexstring)
        end
        @pending_path_challenges.clear
      end

      unless @pending_path_responses.empty?
        @pending_path_responses.each do |data|
          packet.frames << PathResponseFrame.new(data)
        end
        @pending_path_responses.clear
      end

      if tls_data
        offset = @crypto_tx_offsets.fetch(space, 0_u64)
        packet.frames << CryptoFrame.new(offset, tls_data)
        @crypto_tx_offsets[space] = offset + tls_data.size.to_u64
      end
      
      # For client Initial packets, RFC 9000 Section 14.1 requires padding to at least 1200 bytes
      if !@is_server && packet.is_a?(LongHeaderPacket) && packet.type == PacketType::Initial
        payload_io = IO::Memory.new
        packet.frames.each &.encode(payload_io)
        payload_size = payload_io.to_slice.size
        
        header_io = IO::Memory.new
        packet.encode_header(header_io)
        VarInt.write(header_io, 1200_u64)
        header_size = header_io.to_slice.size
        
        current_size = header_size + 4 + payload_size + 16
        if current_size < 1200
          padding_needed = 1200 - current_size
          padding_needed.times do
            packet.frames << PaddingFrame.new
          end
        end
      end
      
      if space.pending_ack && !space.received_pns.empty?
        space.received_pns.sort!
        largest = space.received_pns.last
        # Count consecutive run from largest downward for first_ack_range
        first_ack_range = 0_u64
        i = space.received_pns.size - 2
        while i >= 0 && space.received_pns[i] == largest - first_ack_range - 1
          first_ack_range += 1
          i -= 1
        end
        packet.frames << AckFrame.new(largest, 0_u64, first_ack_range)
        space.pending_ack = false
        # Remove only the contiguous top range we just acknowledged; keep any gaps
        ack_min = largest - first_ack_range
        space.received_pns.reject! { |pn| pn >= ack_min && pn <= largest }
      end
      
      # ENFORCE CONGESTION CONTROL
      if (space == @space_app || space == @space_zero_rtt) && @recovery.can_send?
        # Aggiungiamo i frame di Flow Control se pendenti
        if @pending_max_data
          packet.frames << MaxDataFrame.new(@max_data_local)
          @pending_max_data = false
        end
        if @pending_data_blocked
          packet.frames << DataBlockedFrame.new(@max_data_remote)
          @pending_data_blocked = false
        end
        @pending_stream_data_blocked.each do |sid|
          if stream = @streams[sid]?
            packet.frames << StreamDataBlockedFrame.new(sid, stream.max_stream_data_remote)
          end
        end
        @pending_stream_data_blocked.clear
        
        @pending_max_stream_data.each do |sid|
          if stream = @streams[sid]?
            packet.frames << MaxStreamDataFrame.new(sid, stream.max_stream_data_local)
          end
        end
        @pending_max_stream_data.clear

        if @pending_max_streams_bidi > 0
          packet.frames << MaxStreamsFrame.new(@pending_max_streams_bidi, true)
          @pending_max_streams_bidi = 0_u64
        end

        # HANDSHAKE_DONE: server tells client the handshake is confirmed, then
        # discards Initial and Handshake keys (RFC 9001 §4.9.2).
        if @pending_handshake_done && @is_server && space == @space_app
          packet.frames << HandshakeDoneFrame.new
          @pending_handshake_done = false
          discard_initial_handshake_keys
        end

        # RESET_STREAM: abort send side of a stream (RFC 9000 §3.4).
        @pending_reset_streams.each do |id, error_code, final_size|
          packet.frames << ResetStreamFrame.new(id, error_code, final_size)
        end
        @pending_reset_streams.clear

        # 1. Drain retransmission queue — one frame per send call to stay within MTU
        if !@lost_frames.empty?
          packet.frames << @lost_frames.shift
        end
        # 2. Datagrams
        while !@queued_datagrams.empty?
          packet.frames << DatagramFrame.new(@queued_datagrams.shift)
        end
        
        # 3. New Stream data
        conn_available = @max_data_remote > @data_sent ? @max_data_remote - @data_sent : 0_u64
        
        @streams.each_value do |stream|
          offset, data, send_fin, blocked_reason = stream.poll_send_data(1200, conn_available)
          
          if data.size > 0 || send_fin
            packet.frames << StreamFrame.new(stream.id, offset, data, send_fin)
            @data_sent += data.size.to_u64
            conn_available -= data.size.to_u64
          end
          
          if blocked_reason == :connection
            packet.frames << DataBlockedFrame.new(@max_data_remote)
          elsif blocked_reason == :stream
            packet.frames << StreamDataBlockedFrame.new(stream.id, stream.max_stream_data_remote)
          end
        end
      end
      
      return 0 if packet.frames.empty?
      
      @send_payload_io.clear
      packet.frames.each &.encode(@send_payload_io)
      payload = @send_payload_io.to_slice

      pn_len = 4
      tag_len = 16
      length = pn_len + payload.size + tag_len

      @send_header_io.clear
      Log.trace { "SEND DEBUG: encoding packet with type #{packet.is_a?(LongHeaderPacket) ? packet.as(LongHeaderPacket).type : "Short"} and pn #{packet.packet_number}" }
      packet.frames.each do |f|
        unless f.is_a?(PaddingFrame)
          Log.trace { "SEND FRAME: #{f.class.name} #{f.inspect}" }
        end
      end
      packet.encode_header(@send_header_io)
      if space != @space_app
        VarInt.write(@send_header_io, length.to_u64)
      end
      header = @send_header_io.to_slice

      @send_ad_io.clear
      @send_ad_io.write header
      IO::ByteFormat::NetworkEndian.encode(packet.packet_number.to_u32, @send_ad_io)
      ad = @send_ad_io.to_slice
      
      # Write ad (header + packet_number) directly into out_buffer — no intermediate alloc.
      ad.copy_to(out_buffer)
      # Encrypt payload directly after ad — eliminates ciphertext Bytes.new + final_io.
      ct_size = space.aead_tx.not_nil!.encrypt_into(ad, packet.packet_number, payload, out_buffer[ad.size..])
      final_size = ad.size + ct_size

      if final_size > out_buffer.size
        Log.error { "SEND: packet too large (#{final_size} bytes), dropping" }
        return 0
      end

      sample = out_buffer[ad.size, 16]
      mask = space.hp_tx.not_nil!.mask(sample)
      space.hp_tx.not_nil!.apply!(out_buffer[0, final_size], header.size, mask, unprotect: false)

      ack_eliciting = packet.frames.any? { |f| !f.is_a?(AckFrame) && !f.is_a?(PaddingFrame) && !f.is_a?(ConnectionCloseFrame) }
      @recovery.on_packet_sent(packet.packet_number, final_size, packet.frames, ack_eliciting, space_id: space_id(space))
      space.packet_number += 1
      active_path.bytes_sent += final_size.to_u64
      final_size
    end

    # Pack multiple QUIC packets (Initial + Handshake + 1-RTT) into one UDP
    # datagram per RFC 9000 §12.2. Long-header packets carry a Length field so
    # the receiver can parse them consecutively; short-header (1-RTT) must be last.
    def send_coalesced(out_buffer : Bytes) : Int32
      total = 0
      3.times do
        remaining = out_buffer[total, out_buffer.size - total]
        n = send(remaining)
        break if n <= 0
        first_byte = remaining[0]
        is_long_header = (first_byte & 0x80) != 0
        total += n
        break unless is_long_header
        break if total >= out_buffer.size - 64
      end
      total
    end

    def initial_stream_limits(stream_id : UInt64) : {UInt64, UInt64}
      bidi = (stream_id % 4 < 2)
      # client-initiated: ID % 2 == 0. server-initiated: ID % 2 == 1.
      # If we are server, local_initiated means ID % 2 == 1.
      # If we are client, local_initiated means ID % 2 == 0.
      local_initiated = (stream_id % 2 == 1) == @is_server

      # Defaults from our own config (for local/incoming limits)
      if bidi
        max_local = local_initiated ? @config.initial_max_stream_data_bidi_remote : @config.initial_max_stream_data_bidi_local
      else
        max_local = local_initiated ? 0_u64 : @config.initial_max_stream_data_uni
      end

      # Peer limits from remote transport parameters (for remote/outgoing limits)
      tp = @tls.remote_transport_parameters
      if tp
        if bidi
          max_remote = local_initiated ? tp.initial_max_stream_data_bidi_local : tp.initial_max_stream_data_bidi_remote
        else
          max_remote = local_initiated ? tp.initial_max_stream_data_uni : 0_u64
        end
      else
        if bidi
          max_remote = local_initiated ? @config.initial_max_stream_data_bidi_local : @config.initial_max_stream_data_bidi_remote
        else
          max_remote = local_initiated ? @config.initial_max_stream_data_uni : 0_u64
        end
      end

      {max_remote, max_local}
    end

    # Raises the inbound bidi stream limit by initial_max_streams_bidi whenever the
    # peer has consumed ≥50% of the current grant.  Queues a MAX_STREAMS frame so
    # the peer never has to block on STREAMS_BLOCKED (RFC 9000 §4.6).
    private def maybe_extend_max_streams_bidi
      if @peer_streams_bidi_opened * 2 >= @max_streams_bidi_local
        @max_streams_bidi_local += @config.initial_max_streams_bidi
        @pending_max_streams_bidi = @max_streams_bidi_local
      end
    end

    private def check_and_apply_remote_tp
      return if @remote_tp_applied
      if tp = @tls.remote_transport_parameters
        @max_data_remote = tp.initial_max_data
        @max_streams_bidi_remote = tp.initial_max_streams_bidi if tp.initial_max_streams_bidi > 0
        @max_streams_uni_remote  = tp.initial_max_streams_uni  if tp.initial_max_streams_uni  > 0
        @streams.each do |stream_id, stream|
          max_remote, _ = initial_stream_limits(stream_id)
          stream.update_max_stream_data(max_remote)
        end
        @remote_tp_applied = true
      end
    end

    def stream_write(stream_id : UInt64, data : Bytes)
      check_and_apply_remote_tp
      stream = @streams[stream_id] ||= begin
        max_remote, max_local = initial_stream_limits(stream_id)
        Stream.new(stream_id, max_remote, max_local)
      end
      stream.write(data)
    end

    def stream_read(stream_id : UInt64, data : Bytes) : Int32
      return 0 unless stream = @streams[stream_id]?
      stream.read(data)
    end

    def send_datagram(data : Bytes)
      @queued_datagrams << data
    end

    def probe_path_mtu(size : UInt64)
      @pmtud_probe_size = size
      @pmtud_probe_pn = nil
    end

    def add_path(id : UInt64, local_address = nil, remote_address = nil) : Path
      initial_cwnd = @config.initial_cwnd_packets.to_u64 * Recovery::MAX_DATAGRAM_SIZE
      path = Path.new(id, initial_cwnd, local_address, remote_address)
      @paths << path
      path
    end

    def get_path(id : UInt64) : Path?
      @paths.find { |p| p.id == id }
    end

    def active_path : Path
      get_path(@active_path_id) || @paths[0]
    end

    def active_path_id=(id : UInt64)
      @active_path_id = id
      @recovery = active_path.recovery
    end

    def trigger_key_update
      client_secret = @client_app_secret
      server_secret = @server_app_secret
      return if client_secret.nil? || server_secret.nil?

      _, _, key_len, _, use_sha384 = cipher_suite_info
      if use_sha384
        next_client = Crypto.derive_next_secret_sha384(client_secret)
        next_server = Crypto.derive_next_secret_sha384(server_secret)
        client_key = Crypto.hkdf_expand_label_sha384(next_client, "quic key", Bytes.empty, key_len)
        client_iv  = Crypto.hkdf_expand_label_sha384(next_client, "quic iv",  Bytes.empty, 12)
        server_key = Crypto.hkdf_expand_label_sha384(next_server, "quic key", Bytes.empty, key_len)
        server_iv  = Crypto.hkdf_expand_label_sha384(next_server, "quic iv",  Bytes.empty, 12)
      else
        next_client = Crypto.derive_next_secret(client_secret)
        next_server = Crypto.derive_next_secret(server_secret)
        client_key = Crypto.hkdf_expand_label(next_client, "quic key", Bytes.empty, key_len)
        client_iv  = Crypto.hkdf_expand_label(next_client, "quic iv",  Bytes.empty, 12)
        server_key = Crypto.hkdf_expand_label(next_server, "quic key", Bytes.empty, key_len)
        server_iv  = Crypto.hkdf_expand_label(next_server, "quic iv",  Bytes.empty, 12)
      end

      @client_app_secret = next_client
      @server_app_secret = next_server

      if @is_server
        @space_app.aead_rx = make_aead(client_key, client_iv)
        @space_app.aead_tx = make_aead(server_key, server_iv)
      else
        @space_app.aead_rx = make_aead(server_key, server_iv)
        @space_app.aead_tx = make_aead(client_key, client_iv)
      end
    end

    # RFC 9001 §4.9.2: discard Initial and Handshake keys once the TLS handshake
    # is confirmed.  Called by the server after sending HANDSHAKE_DONE and by the
    # client upon receiving it.  Packets arriving on those spaces are ignored (their
    # AEAD is nil, so recv() skips them with `next if aead_rx.nil?`).
    private def discard_initial_handshake_keys
      @space_initial.aead_rx   = nil
      @space_initial.aead_tx   = nil
      @space_initial.hp_rx     = nil
      @space_initial.hp_tx     = nil
      @space_handshake.aead_rx = nil
      @space_handshake.aead_tx = nil
      @space_handshake.hp_rx   = nil
      @space_handshake.hp_tx   = nil
      Log.debug { "Discarded Initial+Handshake keys (RFC 9001 §4.9.2)" }
    end

    private def setup_initial_secrets(dcid : Bytes)
      client_secret, server_secret = Crypto.derive_initial_secrets(dcid)
      
      client_key = Crypto.hkdf_expand_label(client_secret, "quic key", Bytes.empty, 16)
      client_iv  = Crypto.hkdf_expand_label(client_secret, "quic iv", Bytes.empty, 12)
      client_hp  = Crypto.hkdf_expand_label(client_secret, "quic hp", Bytes.empty, 16)
      
      server_key = Crypto.hkdf_expand_label(server_secret, "quic key", Bytes.empty, 16)
      server_iv  = Crypto.hkdf_expand_label(server_secret, "quic iv", Bytes.empty, 12)
      server_hp  = Crypto.hkdf_expand_label(server_secret, "quic hp", Bytes.empty, 16)

      if @is_server
        @space_initial.aead_rx = Crypto::AEAD.new(client_key, client_iv)
        @space_initial.hp_rx   = Crypto::HeaderProtection.new(client_hp)
        @space_initial.aead_tx = Crypto::AEAD.new(server_key, server_iv)
        @space_initial.hp_tx   = Crypto::HeaderProtection.new(server_hp)
      else
        @space_initial.aead_rx = Crypto::AEAD.new(server_key, server_iv)
        @space_initial.hp_rx   = Crypto::HeaderProtection.new(server_hp)
        @space_initial.aead_tx = Crypto::AEAD.new(client_key, client_iv)
        @space_initial.hp_tx   = Crypto::HeaderProtection.new(client_hp)
      end
    end

    # Returns {aead_name, hp_name, key_len, hp_len, use_sha384} for the
    # negotiated TLS 1.3 cipher suite (RFC 9001 §5.3).
    private def cipher_suite_info : {String, String, Int32, Int32, Bool}
      case @tls.cipher_suite_name
      when "TLS_AES_256_GCM_SHA384"
        {"AES-256-GCM", "AES-256-ECB", 32, 32, true}
      when "TLS_CHACHA20_POLY1305_SHA256"
        {"CHACHA20-POLY1305", "CHACHA20", 32, 32, false}
      else
        {"AES-128-GCM", "AES-128-ECB", 16, 16, false}
      end
    end

    private def derive_quic_keys(secret : Bytes) : {Bytes, Bytes, Bytes}
      aead_name, hp_name, key_len, hp_len, use_sha384 = cipher_suite_info
      if use_sha384
        key = Crypto.hkdf_expand_label_sha384(secret, "quic key", Bytes.empty, key_len)
        iv  = Crypto.hkdf_expand_label_sha384(secret, "quic iv",  Bytes.empty, 12)
        hp  = Crypto.hkdf_expand_label_sha384(secret, "quic hp",  Bytes.empty, hp_len)
      else
        key = Crypto.hkdf_expand_label(secret, "quic key", Bytes.empty, key_len)
        iv  = Crypto.hkdf_expand_label(secret, "quic iv",  Bytes.empty, 12)
        hp  = Crypto.hkdf_expand_label(secret, "quic hp",  Bytes.empty, hp_len)
      end
      {key, iv, hp}
    end

    private def make_aead(key : Bytes, iv : Bytes) : Crypto::AEAD
      aead_name, _, _, _, _ = cipher_suite_info
      Crypto::AEAD.new(key, iv, aead_name)
    end

    private def make_hp(hp : Bytes) : Crypto::HeaderProtection
      _, hp_name, _, _, _ = cipher_suite_info
      Crypto::HeaderProtection.new(hp, hp_name)
    end

    private def handle_secret(label : String, secret : Bytes)
      Log.trace { "SECRET DERIVATION: label=#{label} secret=#{secret.hexstring}" }
      key, iv, hp = derive_quic_keys(secret)

      case label
      when "CLIENT_EARLY_TRAFFIC_SECRET"
        # 0-RTT write key (client) / read key (server)
        if @is_server
          @space_zero_rtt.aead_rx = make_aead(key, iv)
          @space_zero_rtt.hp_rx   = make_hp(hp)
        else
          @space_zero_rtt.aead_tx = make_aead(key, iv)
          @space_zero_rtt.hp_tx   = make_hp(hp)
        end
        Log.trace { "0-RTT keys installed (#{@is_server ? "read" : "write"})" }
      when "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        @client_handshake_secret = secret
        if @is_server
          @space_handshake.aead_rx = make_aead(key, iv)
          @space_handshake.hp_rx   = make_hp(hp)
        else
          @space_handshake.aead_tx = make_aead(key, iv)
          @space_handshake.hp_tx   = make_hp(hp)
        end
      when "SERVER_HANDSHAKE_TRAFFIC_SECRET"
        @server_handshake_secret = secret
        if @is_server
          @space_handshake.aead_tx = make_aead(key, iv)
          @space_handshake.hp_tx   = make_hp(hp)
        else
          @space_handshake.aead_rx = make_aead(key, iv)
          @space_handshake.hp_rx   = make_hp(hp)
        end
      when "CLIENT_TRAFFIC_SECRET_0"
        @client_app_secret = secret
        if @is_server
          @space_app.aead_rx = make_aead(key, iv)
          @space_app.hp_rx   = make_hp(hp)
        else
          @space_app.aead_tx = make_aead(key, iv)
          @space_app.hp_tx   = make_hp(hp)
        end
      when "SERVER_TRAFFIC_SECRET_0"
        @server_app_secret = secret
        if @is_server
          @space_app.aead_tx = make_aead(key, iv)
          @space_app.hp_tx   = make_hp(hp)
        else
          @space_app.aead_rx = make_aead(key, iv)
          @space_app.hp_rx   = make_hp(hp)
        end
      end
    end

    private def parse_transport_parameters_from_stream(io : IO)
      io.rewind
      while io.size - io.pos >= 4
        start_pos = io.pos
        type = io.read_byte.not_nil!
        
        len_bytes = Bytes.new(3)
        io.read_fully(len_bytes)
        length = (len_bytes[0].to_u32 << 16) | (len_bytes[1].to_u32 << 8) | len_bytes[2].to_u32
        
        if io.size - io.pos < length
          io.seek(start_pos)
          break
        end
        
        msg_bytes = Bytes.new(4 + length)
        io.seek(start_pos)
        io.read_fully(msg_bytes)
        
        if tp_bytes = Connection.extract_transport_parameters(msg_bytes)
          begin
            tp_io = IO::Memory.new(tp_bytes)
            tp = TransportParameters.decode(tp_io)
            @tls.set_remote_tp(tp)
            Log.trace { "Successfully parsed remote transport parameters from crypto stream!" }
          rescue ex
            Log.trace { "Error decoding transport parameters from crypto stream: #{ex.message}" }
          end
        end
      end
      if io.pos > 0
        remaining = io.size - io.pos
        if remaining > 0
          temp = Bytes.new(remaining)
          io.read_fully(temp)
          io.clear
          io.write(temp)
        else
          io.clear
        end
      end
    end

    def self.extract_transport_parameters(handshake_bytes : Bytes) : Bytes?
      return nil if handshake_bytes.size < 4
      type = handshake_bytes[0]
      return nil unless type == 1 || type == 8
      
      io = IO::Memory.new(handshake_bytes)
      io.skip(4)
      
      if type == 1
        return nil if io.size - io.pos < 34
        io.skip(2)
        io.skip(32)
        sess_id_len = io.read_byte || return nil
        io.skip(sess_id_len)
        
        ciphers_len = io.read_bytes(UInt16, IO::ByteFormat::BigEndian) rescue return nil
        io.skip(ciphers_len)
        
        comp_len = io.read_byte || return nil
        io.skip(comp_len)
      end
      
      ext_total_len = io.read_bytes(UInt16, IO::ByteFormat::BigEndian) rescue return nil
      end_pos = io.pos + ext_total_len
      
      while io.pos < end_pos && io.pos < io.size
        ext_type = io.read_bytes(UInt16, IO::ByteFormat::BigEndian) rescue break
        ext_len = io.read_bytes(UInt16, IO::ByteFormat::BigEndian) rescue break
        if ext_type == 57
          tp_bytes = Bytes.new(ext_len)
          io.read_fully(tp_bytes)
          return tp_bytes
        else
          io.skip(ext_len)
        end
      end
      nil
    end

    def closed? : Bool
      @closed
    end
  end
end
