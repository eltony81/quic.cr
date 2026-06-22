require "./sys/linux"
require "./sys/txtime"
require "socket"

module QUIC
  # Batches outgoing UDP datagrams and flushes them with the minimum number of
  # syscalls by selecting the best available kernel API:
  #
  #  1. **GSO path** (best): when all queued packets share the same size and
  #     destination, one `sendmsg` + `UDP_SEGMENT` cmsg collapses N packets into
  #     a single kernel call. Requires kernel ≥ 4.18 and NIC tx-checksum offload.
  #
  #  2. **sendmmsg path** (good): batches heterogeneous packets in one syscall.
  #     Requires Linux 3.0+.
  #
  #  3. **sendto fallback** (safe): individual sendto per packet; used only when
  #     both of the above fail at runtime.
  #
  # Optionally pairs with SO_TXTIME to attach per-packet TAI timestamps so the
  # fq qdisc releases packets at a QUIC-pacing-computed schedule.
  # SO_TXTIME requires kernel ≥ 4.19 and qdisc `fq` (not `fq_codel`).
  #
  # All buffers are pre-allocated at construction; add/flush are allocation-free.
  # Not thread-safe — call only from one fiber at a time.
  class BatchSender
    BATCH_SIZE = 64
    MAX_PKT    = 1500 # conservative MTU ceiling
    GSO_MAX    = BATCH_SIZE * MAX_PKT # max coalesced buffer = 96 KB

    # CMSG_SPACE(sizeof(uint64_t)) = 24 bytes  (for SCM_TXTIME)
    # CMSG_SPACE(sizeof(uint16_t)) = 24 bytes  (for UDP_SEGMENT)
    # Combined: 48 bytes when both are active
    TXTIME_CMSG_LEN =  24
    GSO_CMSG_LEN    =  24
    COMBINED_CTRL   =  48  # txtime + gso together

    @fd : Int32
    @count : Int32

    @pkt_bufs : Array(Bytes)
    @pkt_sizes : Array(Int32)

    # Hold IPAddress references so to_unsafe pointers stay valid until flush.
    @addrs : Array(Socket::IPAddress?)

    # Pre-allocated C struct arrays for sendmmsg path.
    @msgvec : Array(LibSys::Mmsghdr)
    @iovecs : Array(LibSys::Iovec)

    # SO_TXTIME / SCM_TXTIME pacing
    @txtime_enabled : Bool = false
    @pacing_rate_bps : Float64 = 0.0
    @next_tx_ns : Int64 = 0
    @ctrl_bufs : Array(Bytes)  # per-packet control buffers (for sendmmsg path)

    # UDP GSO
    @gso_enabled : Bool = false
    @gso_buf : Bytes           # pre-allocated coalescing buffer
    @gso_ctrl : Bytes          # 24-byte cmsg buffer for UDP_SEGMENT

    def initialize(socket : UDPSocket)
      @fd    = socket.fd
      @count = 0
      @pkt_bufs  = Array.new(BATCH_SIZE) { Bytes.new(MAX_PKT) }
      @pkt_sizes = Array.new(BATCH_SIZE, 0)
      @addrs     = Array(Socket::IPAddress?).new(BATCH_SIZE, nil)
      @msgvec    = Array.new(BATCH_SIZE) { LibSys::Mmsghdr.new }
      @iovecs    = Array.new(BATCH_SIZE) { LibSys::Iovec.new }
      @ctrl_bufs = Array.new(BATCH_SIZE) { Bytes.new(TXTIME_CMSG_LEN, 0_u8) }
      @gso_buf   = Bytes.new(GSO_MAX, 0_u8)
      @gso_ctrl  = Bytes.new(GSO_CMSG_LEN, 0_u8)
    end

    # -------------------------------------------------------------------------
    # Feature detection

    # Enable SO_TXTIME kernel pacing. Returns true on success.
    # Requires fq qdisc — silently degrades with fq_codel (sendmmsg detects at flush).
    def enable_txtime! : Bool
      cfg = LibSys::SockTxtime.new
      cfg.clockid = LibC::CLOCK_TAI.to_i32
      cfg.flags   = 0_u32
      ret = LibC.setsockopt(
        @fd, LibC::SOL_SOCKET, LibSys::SO_TXTIME,
        pointerof(cfg).as(Void*), sizeof(LibSys::SockTxtime).to_u32
      )
      @txtime_enabled = ret == 0
    end

    def txtime_enabled? : Bool
      @txtime_enabled
    end

    def pacing_rate_bps=(rate : Float64)
      @pacing_rate_bps = rate
      @next_tx_ns = 0_i64
    end

    # Enable UDP GSO fragmentation. Returns true when the kernel supports it.
    # Probes getsockopt(UDP_SEGMENT); falls back at first EIO if the NIC lacks
    # tx-checksum offload.
    def enable_gso!(socket : UDPSocket) : Bool
      val = 0_u32
      len = sizeof(UInt32).to_u32
      ret = LibC.getsockopt(socket.fd, LibSys::IPPROTO_UDP, LibSys::UDP_SEGMENT,
                            pointerof(val).as(Void*), pointerof(len))
      @gso_enabled = ret == 0
    end

    def gso_enabled? : Bool
      @gso_enabled
    end

    # -------------------------------------------------------------------------
    # Hot path

    # Enqueue one datagram. Auto-flushes when the batch is full.
    # Datagrams larger than MAX_PKT (coalesced multi-QUIC-packet datagrams)
    # are sent immediately via a single sendto to avoid truncation.
    def add(data : Bytes, addr : Socket::IPAddress) : Nil
      if data.size > MAX_PKT
        # Coalesced QUIC packet (Initial+Handshake etc.) — already "batched"
        # at the QUIC layer, just needs one direct send.
        flush  # drain any pending ordinary packets first
        namelen = addr.family == Socket::Family::INET ? 16_u32 : 28_u32
        LibC.sendto(@fd, data.to_unsafe.as(Void*), data.size.to_u64, 0,
                    addr.to_unsafe.as(LibC::Sockaddr*), namelen)
        return
      end
      i = @count
      data.copy_to(@pkt_bufs[i])
      @pkt_sizes[i] = data.size
      @addrs[i] = addr
      @count += 1
      flush if @count >= BATCH_SIZE
    end

    # Transmit all buffered datagrams, choosing the best available path.
    def flush : Nil
      return if @count == 0
      if @gso_enabled && gso_eligible?
        flush_gso
      else
        flush_sendmmsg
      end
      @count = 0
    end

    def pending? : Bool
      @count > 0
    end

    # -------------------------------------------------------------------------
    # GSO flush path

    # Returns true when all queued packets share the same size and destination —
    # the precondition for collapsing them with UDP_SEGMENT.
    private def gso_eligible? : Bool
      return false if @count < 2
      size0 = @pkt_sizes[0]
      addr0 = @addrs[0].not_nil!
      a0_ip   = addr0.address
      a0_port = addr0.port
      i = 1
      while i < @count
        a = @addrs[i].not_nil!
        return false unless @pkt_sizes[i] == size0 && a.address == a0_ip && a.port == a0_port
        i += 1
      end
      true
    end

    private def flush_gso : Nil
      seg_size = @pkt_sizes[0]
      addr     = @addrs[0].not_nil!
      total    = seg_size * @count

      # Pack all segments into @gso_buf
      @count.times do |i|
        @pkt_bufs[i][0, seg_size].copy_to(@gso_buf[i * seg_size, seg_size])
      end

      # iovec covering the entire coalesced buffer
      iov = LibC::Iovec.new
      iov.iov_base = @gso_buf.to_unsafe.as(Void*)
      iov.iov_len  = total.to_u64

      # Control message: UDP_SEGMENT
      write_gso_cmsg(@gso_ctrl, seg_size.to_u16)

      namelen = addr.family == Socket::Family::INET ? 16_u32 : 28_u32
      hdr = LibC::Msghdr.new
      hdr.msg_name       = addr.to_unsafe.as(Void*)
      hdr.msg_namelen    = namelen
      hdr.msg_iov        = pointerof(iov)
      hdr.msg_iovlen     = 1_u64
      hdr.msg_control    = @gso_ctrl.to_unsafe.as(Void*)
      hdr.msg_controllen = GSO_CMSG_LEN.to_u64
      hdr.msg_flags      = 0

      ret = LibC.sendmsg(@fd, pointerof(hdr), 0)
      if ret < 0
        # EIO means the NIC has no tx-checksum offload — disable GSO permanently.
        @gso_enabled = false
        flush_sendmmsg  # retry the same batch without GSO
      end
    end

    # Writes a UDP_SEGMENT cmsghdr into a 24-byte buffer.
    # Layout: cmsg_len(8) + cmsg_level(4) + cmsg_type(4) + seg_size(2) + pad(6)
    private def write_gso_cmsg(buf : Bytes, seg_size : UInt16) : Nil
      (buf.to_unsafe +  0).as(UInt64*).value = 18_u64         # cmsg_len = 16 + 2
      (buf.to_unsafe +  8).as(Int32*).value  = LibSys::IPPROTO_UDP.to_i32
      (buf.to_unsafe + 12).as(Int32*).value  = LibSys::UDP_SEGMENT.to_i32
      (buf.to_unsafe + 16).as(UInt16*).value = seg_size
      # bytes 18-23: zero padding (buffer was 0-initialised)
    end

    # -------------------------------------------------------------------------
    # sendmmsg flush path

    private def flush_sendmmsg : Nil
      now_ns = @txtime_enabled ? tai_now_ns : 0_i64
      if @txtime_enabled && @next_tx_ns < now_ns
        @next_tx_ns = now_ns
      end

      mv = @msgvec.to_unsafe
      iv = @iovecs.to_unsafe

      @count.times do |i|
        addr = @addrs[i].not_nil!

        iov = LibSys::Iovec.new
        iov.iov_base = @pkt_bufs[i].to_unsafe.as(Void*)
        iov.iov_len  = @pkt_sizes[i].to_u64
        iv[i] = iov

        namelen = addr.family == Socket::Family::INET ? 16_u32 : 28_u32
        hdr = LibSys::Msghdr.new
        hdr.msg_name    = addr.to_unsafe.as(Void*)
        hdr.msg_namelen = namelen
        hdr.msg_iov     = iv + i
        hdr.msg_iovlen  = 1_u64
        hdr.msg_flags   = 0

        if @txtime_enabled
          tx_ns = schedule_packet(i, now_ns)
          write_txtime_cmsg(@ctrl_bufs[i], tx_ns)
          hdr.msg_control    = @ctrl_bufs[i].to_unsafe.as(Void*)
          hdr.msg_controllen = TXTIME_CMSG_LEN.to_u64
        else
          hdr.msg_control    = Pointer(Void).null
          hdr.msg_controllen = 0_u64
        end

        mm = LibSys::Mmsghdr.new
        mm.msg_hdr = hdr
        mm.msg_len = 0_u32
        mv[i] = mm
      end

      ret = LibSys.sendmmsg(@fd, mv, @count.to_u32, 0)

      if ret < 0
        if @txtime_enabled
          # fq_codel doesn't support SCM_TXTIME — disable and retry without timestamps
          @txtime_enabled = false
          @count.times do |i|
            mv[i].msg_hdr.msg_control    = Pointer(Void).null
            mv[i].msg_hdr.msg_controllen = 0_u64
          end
          ret = LibSys.sendmmsg(@fd, mv, @count.to_u32, 0)
        end

        if ret < 0
          # Final fallback: individual sendto per packet
          @count.times do |i|
            addr = @addrs[i].not_nil!
            namelen = addr.family == Socket::Family::INET ? 16_u32 : 28_u32
            LibC.sendto(
              @fd,
              @pkt_bufs[i].to_unsafe.as(Void*),
              @pkt_sizes[i].to_u64,
              0,
              addr.to_unsafe.as(LibC::Sockaddr*),
              namelen
            )
          end
        end
      end
    end

    # -------------------------------------------------------------------------
    # SO_TXTIME helpers

    private def tai_now_ns : Int64
      ts = LibC::Timespec.new
      LibC.clock_gettime(LibC::CLOCK_TAI, pointerof(ts))
      ts.tv_sec.to_i64 &* 1_000_000_000_i64 &+ ts.tv_nsec.to_i64
    end

    private def schedule_packet(i : Int32, now_ns : Int64) : Int64
      tx = @next_tx_ns
      if @pacing_rate_bps > 0.0
        gap_ns = (@pkt_sizes[i].to_f * 1_000_000_000.0 / @pacing_rate_bps).to_i64
        @next_tx_ns &+= gap_ns
      end
      tx
    end

    # SCM_TXTIME cmsghdr into a 24-byte buffer.
    # Layout: cmsg_len(8) + cmsg_level(4) + cmsg_type(4) + tx_ns(8)
    private def write_txtime_cmsg(buf : Bytes, tx_ns : Int64) : Nil
      (buf.to_unsafe +  0).as(UInt64*).value = 24_u64              # cmsg_len = 16 + 8
      (buf.to_unsafe +  8).as(Int32*).value  = 1_i32               # SOL_SOCKET
      (buf.to_unsafe + 12).as(Int32*).value  = LibSys::SCM_TXTIME.to_i32
      (buf.to_unsafe + 16).as(UInt64*).value = tx_ns.to_u64
    end
  end
end
