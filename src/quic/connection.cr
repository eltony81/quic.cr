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
    property recovery : Recovery = Recovery.new
    property? validated : Bool = false
    property bytes_sent : UInt64 = 0
    property bytes_received : UInt64 = 0

    def initialize(@id, @local_address = nil, @remote_address = nil)
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
    
    # Event notification channels to avoid sleep polling
    getter handshake_chan : Channel(Bool) = Channel(Bool).new(1)
    getter stream_chans : Hash(UInt64, Channel(Bool)) = {} of UInt64 => Channel(Bool)
    
    def handshake_complete? : Bool
      @tls.handshake_complete?
    end

    @pending_path_responses = [] of Bytes
    @pending_path_challenges = [] of Bytes
    @path_validated = false

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

    @client_finished_sent = false
    @server_finished_sent = false
    
    @pending_initial_tls : Bytes? = nil
    @pending_handshake_tls : Bytes? = nil
    @remote_tp_applied : Bool = false

    @initial_handshake_bytes = IO::Memory.new
    @handshake_handshake_bytes = IO::Memory.new

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

      @paths << Path.new(0)
      @recovery = @paths[0].recovery

      @tls = TLS.new(@config, @is_server)
      @tls.on_secret = ->(label : String, secret : Bytes) {
        handle_secret(label, secret)
      }
      @max_data_local = @config.initial_max_data
      unless @is_server
        @dcid = Random::Secure.random_bytes(8)
        @scid = Random::Secure.random_bytes(8)
        setup_initial_secrets(@dcid.not_nil!)
        
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

      final_data = data.dup
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
                when 0x00 then @space_initial # Initial
                when 0x01 then @space_initial # HelloRetryRequest (Initial space)
                when 0x02 then @space_handshake # Handshake
                else @space_initial # Default fallback
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
        plaintext = space.aead_rx.not_nil!.decrypt(ad, pn, ciphertext)
        
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
      else
        # Short Header
        dcid = Bytes.new(8)
        io.read_fully(dcid)
        pn_offset = io.pos.to_i
        
        return data.size unless @space_app.hp_rx

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

    private def handle_frame(frame : Frame, space : PacketNumberSpace)
      unless frame.is_a?(PaddingFrame)
        Log.trace { "RECV FRAME: #{frame.class} - #{frame.inspect}" }
      end
      case frame
      when CryptoFrame
        Log.trace { "RECV CRYPTO FRAME: offset=#{frame.offset} size=#{frame.data.size}" }
        handle_crypto_frame(frame, space)
      when StreamFrame
        stream = @streams[frame.id] ||= begin
          max_remote, max_local = initial_stream_limits(frame.id)
          Stream.new(frame.id, max_remote, max_local)
        end
        
        if @data_received + frame.data.size > @max_data_local
          close(0x01_u64, "Flow control error")
          return
        end
        @data_received += frame.data.size
        stream.receive_data(frame.offset, frame.data)
        stream.close_remote if frame.fin
        
        # Notify channel that stream has new data/state update
        if chan = @stream_chans[frame.id]?
          select
          when chan.send(true)
          else
          end
        end
      when AckFrame
        @paths.each &.recovery.on_ack_received(frame)
        
        # Trigger loss detection
        lost_pkts = @recovery.detect_lost_packets(frame.largest_acknowledged)
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
        
        # If handshake has completed, notify
        if @tls.handshake_complete?
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
                else
                  @space_app.aead_tx ? @space_app : @space_initial
                end
        tls_data = nil
      end

      if tls_data.nil? && !space.pending_ack && !(@closed && !@close_sent) && @streams.all? { |_, s| !s.has_send_data? } && @pending_path_responses.empty? && @lost_frames.empty?
        Log.trace { "SEND DEBUG: return 0 (no tls_data, no ack, no stream data, no lost frames)" }
        return 0
      end

      packet = if space == @space_app
                 return 0 if @dcid.nil?
                 ShortHeaderPacket.new(@dcid.not_nil!)
               else
                 return 0 if @scid.nil? || @dcid.nil?
                 packet_type = space == @space_initial ? PacketType::Initial : (space == @space_handshake ? PacketType::Handshake : PacketType::Short)
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
      
      if space.pending_ack && !space.received_pns.empty?
        largest = space.received_pns.max
        packet.frames << AckFrame.new(largest, 0_u64, 0_u64)
        space.pending_ack = false
      end
      
      # ENFORCE CONGESTION CONTROL
      if space == @space_app && @recovery.can_send?
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

        # 1. Drain retransmission queue
        while !@lost_frames.empty?
          packet.frames << @lost_frames.shift
        end
        # 2. Datagrams
        while !@queued_datagrams.empty?
          packet.frames << DatagramFrame.new(@queued_datagrams.shift)
        end
        
        # 3. New Stream data
        conn_available = @max_data_remote > @data_sent ? @max_data_remote - @data_sent : 0_u64
        
        @streams.each_value do |stream|
          offset, data, send_fin, blocked_reason = stream.poll_send_data(1000, conn_available)
          
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
      
      payload_io = IO::Memory.new
      packet.frames.each &.encode(payload_io)
      payload = payload_io.to_slice
      
      pn_len = 4
      tag_len = 16
      length = pn_len + payload.size + tag_len
      
      header_io = IO::Memory.new
      Log.trace { "SEND DEBUG: encoding packet with type #{packet.is_a?(LongHeaderPacket) ? packet.as(LongHeaderPacket).type : "Short"} and pn #{packet.packet_number}" }
      packet.frames.each do |f|
        unless f.is_a?(PaddingFrame)
          Log.trace { "SEND FRAME: #{f.class.name} #{f.inspect}" }
        end
      end
      packet.encode_header(header_io)
      if space != @space_app
        VarInt.write(header_io, length.to_u64)
      end
      header = header_io.to_slice
      
      ad_io = IO::Memory.new
      ad_io.write header
      IO::ByteFormat::NetworkEndian.encode(packet.packet_number.to_u32, ad_io)
      ad = ad_io.to_slice
      
      ciphertext = space.aead_tx.not_nil!.encrypt(ad, packet.packet_number, payload)
      
      final_io = IO::Memory.new
      final_io.write ad
      final_io.write ciphertext
      final_data = final_io.to_slice
      
      sample = ciphertext[0..15]
      mask = space.hp_tx.not_nil!.mask(sample)
      space.hp_tx.not_nil!.apply!(final_data, header.size, mask, unprotect: false)

      ack_eliciting = packet.frames.any? { |f| !f.is_a?(AckFrame) && !f.is_a?(PaddingFrame) && !f.is_a?(ConnectionCloseFrame) }
      @recovery.on_packet_sent(packet.packet_number, final_data.size, packet.frames, ack_eliciting)
      space.packet_number += 1
      active_path.bytes_sent += final_data.size.to_u64
      
      out_buffer[0, final_data.size].copy_from(final_data)
      final_data.size
    end

    def initial_stream_limits(stream_id : UInt64) : {UInt64, UInt64}
      bidi = (stream_id % 4 < 2)
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

    private def check_and_apply_remote_tp
      return if @remote_tp_applied
      if tp = @tls.remote_transport_parameters
        @max_data_remote = tp.initial_max_data
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
      path = Path.new(id, local_address, remote_address)
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

      next_client = Crypto.derive_next_secret(client_secret)
      next_server = Crypto.derive_next_secret(server_secret)

      @client_app_secret = next_client
      @server_app_secret = next_server

      client_key = Crypto.hkdf_expand_label(next_client, "quic key", Bytes.empty, 16)
      client_iv  = Crypto.hkdf_expand_label(next_client, "quic iv", Bytes.empty, 12)
      server_key = Crypto.hkdf_expand_label(next_server, "quic key", Bytes.empty, 16)
      server_iv  = Crypto.hkdf_expand_label(next_server, "quic iv", Bytes.empty, 12)

      if @is_server
        @space_app.aead_rx = Crypto::AEAD.new(client_key, client_iv)
        @space_app.aead_tx = Crypto::AEAD.new(server_key, server_iv)
      else
        @space_app.aead_rx = Crypto::AEAD.new(server_key, server_iv)
        @space_app.aead_tx = Crypto::AEAD.new(client_key, client_iv)
      end
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

    private def handle_secret(label : String, secret : Bytes)
      Log.trace { "SECRET DERIVATION: label=#{label} secret=#{secret.hexstring}" }
      key = Crypto.hkdf_expand_label(secret, "quic key", Bytes.empty, 16)
      iv  = Crypto.hkdf_expand_label(secret, "quic iv", Bytes.empty, 12)
      hp  = Crypto.hkdf_expand_label(secret, "quic hp", Bytes.empty, 16)

      case label
      when "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        @client_handshake_secret = secret
        if @is_server
          @space_handshake.aead_rx = Crypto::AEAD.new(key, iv)
          @space_handshake.hp_rx   = Crypto::HeaderProtection.new(hp)
        else
          @space_handshake.aead_tx = Crypto::AEAD.new(key, iv)
          @space_handshake.hp_tx   = Crypto::HeaderProtection.new(hp)
        end
      when "SERVER_HANDSHAKE_TRAFFIC_SECRET"
        @server_handshake_secret = secret
        if @is_server
          @space_handshake.aead_tx = Crypto::AEAD.new(key, iv)
          @space_handshake.hp_tx   = Crypto::HeaderProtection.new(hp)
        else
          @space_handshake.aead_rx = Crypto::AEAD.new(key, iv)
          @space_handshake.hp_rx   = Crypto::HeaderProtection.new(hp)
        end
      when "CLIENT_TRAFFIC_SECRET_0"
        @client_app_secret = secret
        if @is_server
          @space_app.aead_rx = Crypto::AEAD.new(key, iv)
          @space_app.hp_rx   = Crypto::HeaderProtection.new(hp)
        else
          @space_app.aead_tx = Crypto::AEAD.new(key, iv)
          @space_app.hp_tx   = Crypto::HeaderProtection.new(hp)
        end
      when "SERVER_TRAFFIC_SECRET_0"
        @server_app_secret = secret
        if @is_server
          @space_app.aead_tx = Crypto::AEAD.new(key, iv)
          @space_app.hp_tx   = Crypto::HeaderProtection.new(hp)
        else
          @space_app.aead_rx = Crypto::AEAD.new(key, iv)
          @space_app.hp_rx   = Crypto::HeaderProtection.new(hp)
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
