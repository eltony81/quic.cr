require "./sys/linux"
require "socket"

module QUIC
  # Receives multiple UDP datagrams per syscall via recvmmsg(2) (Linux 2.6.33+).
  # Integrates with Crystal's non-blocking IO: blocking_drain waits via IO.select
  # (Crystal's fiber-aware epoll), then drains all queued packets with MSG_DONTWAIT.
  #
  # With UDP_GRO enabled, the kernel coalesces multiple equal-size datagrams into
  # one large buffer per recvmmsg entry and reports the segment size via a UDP_GRO
  # cmsg. each_segment reads that cmsg and yields each individual QUIC packet.
  #
  # All buffers are pre-allocated at construction; blocking_drain/each_segment are
  # allocation-free on the hot path.
  class BatchReceiver
    BATCH_SIZE   = 64
    # GRO coalesces up to GRO_MAX_SIZE=65535 bytes per slot (Linux kernel limit).
    # Without GRO, QUIC packets are always ≤1500 bytes. We use 65536 (64KB) for
    # all slots so enable_gro! never truncates a coalesced superpacket.
    MAX_PKT      = 65536
    CTRL_BUF_SZ  = 32   # CMSG_SPACE(sizeof(__u16)) = 24; 32 keeps 8-byte alignment

    MSG_DONTWAIT = 0x40
    SOL_UDP      = 17
    UDP_GRO      = 104

    # struct cmsghdr layout on x86-64 Linux:
    #   offset 0: cmsg_len   (size_t, 8 bytes)
    #   offset 8: cmsg_level (int,    4 bytes)
    #   offset 12: cmsg_type (int,    4 bytes)
    #   offset 16: data (gso_size: __u16 for UDP_GRO)
    CMSG_HDR  = 16_u64
    CMSG_ALGN =  8_u64

    @fd          : Int32
    @pkt_bufs    : Array(Bytes)
    @addr_bufs   : Array(Bytes)
    @ctrl_bufs   : Array(Bytes)
    @iovecs      : Array(LibSys::Iovec)
    @msgvec      : Array(LibSys::Mmsghdr)
    @count       : Int32 = 0
    @gro_enabled : Bool  = false

    def initialize(socket : UDPSocket)
      @fd = socket.fd
      @pkt_bufs  = Array.new(BATCH_SIZE) { Bytes.new(MAX_PKT, 0_u8) }
      @addr_bufs = Array.new(BATCH_SIZE) { Bytes.new(28, 0_u8) }
      @ctrl_bufs = Array.new(BATCH_SIZE) { Bytes.new(CTRL_BUF_SZ, 0_u8) }
      @iovecs    = Array.new(BATCH_SIZE) { LibSys::Iovec.new }
      @msgvec    = Array.new(BATCH_SIZE) { LibSys::Mmsghdr.new }

      # Crystal struct arrays: arr[i].field = x silently modifies a temporary copy.
      # Build each struct in a local variable and write it back via the raw pointer.
      iov_ptr  = @iovecs.to_unsafe
      mmsg_ptr = @msgvec.to_unsafe

      BATCH_SIZE.times do |i|
        iov = LibSys::Iovec.new
        iov.iov_base = @pkt_bufs[i].to_unsafe.as(Void*)
        iov.iov_len  = MAX_PKT.to_u64
        iov_ptr[i] = iov

        hdr = LibSys::Msghdr.new
        hdr.msg_name       = @addr_bufs[i].to_unsafe.as(Void*)
        hdr.msg_namelen    = 28_u32
        hdr.msg_iov        = iov_ptr + i
        hdr.msg_iovlen     = 1_u64
        hdr.msg_control    = @ctrl_bufs[i].to_unsafe.as(Void*)
        hdr.msg_controllen = 0_u64   # zero until enable_gro! is called
        hdr.msg_flags      = 0

        mm = LibSys::Mmsghdr.new
        mm.msg_hdr = hdr
        mm.msg_len = 0_u32
        mmsg_ptr[i] = mm
      end
    end

    # Enable UDP_GRO on the socket. Returns true if the kernel accepted the option.
    # When enabled, blocking_drain and each_segment transparently handle coalesced buffers.
    def enable_gro!(socket : UDPSocket) : Bool
      val = 1_i32
      ret = LibC.setsockopt(socket.fd, SOL_UDP, UDP_GRO,
                            pointerof(val).as(Void*), sizeof(Int32).to_u32)
      @gro_enabled = ret == 0
      if @gro_enabled
        # Open the control-message window so the kernel fills the UDP_GRO cmsg.
        mmsg_ptr = @msgvec.to_unsafe
        BATCH_SIZE.times do |i|
          mm = mmsg_ptr[i]
          hdr = mm.msg_hdr
          hdr.msg_controllen = CTRL_BUF_SZ.to_u64
          mm.msg_hdr = hdr
          mmsg_ptr[i] = mm
        end
      end
      @gro_enabled
    end

    def gro_enabled? : Bool
      @gro_enabled
    end

    # Block the current fiber until the socket is readable, then drain all available
    # packets in one recvmmsg call.  Uses IO.select for fiber-aware epoll wait so
    # the OS thread is not blocked.  Returns the number of recvmmsg entries (each
    # may contain multiple GRO segments — use each_segment to iterate them).
    def blocking_drain(socket : UDPSocket) : Int32
      loop do
        reset_for_recv
        ret = LibSys.recvmmsg(@fd, @msgvec.to_unsafe, BATCH_SIZE.to_u32, MSG_DONTWAIT, nil)
        if ret > 0
          @count = ret
          return ret
        end
        if ret < 0 && Errno.value == Errno::EAGAIN
          Crystal::EventLoop.current.wait_readable(socket)  # yield fiber to epoll
          next
        end
        @count = 0
        return 0
      end
    end

    # Non-blocking drain (legacy): call right after a blocking receive elsewhere.
    # Returns the number of additional messages received.
    def drain_nowait : Int32
      reset_for_recv
      ret = LibSys.recvmmsg(@fd, @msgvec.to_unsafe, BATCH_SIZE.to_u32, MSG_DONTWAIT, nil)
      @count = ret > 0 ? ret : 0
    end

    # Yield (data, addr) for each QUIC packet in batch slot i.
    # When GRO is active, one slot may contain N coalesced packets; this method
    # reads the UDP_GRO cmsg to learn gso_size and splits the buffer accordingly.
    def each_segment(i : Int32, & : Bytes, Socket::IPAddress -> Nil)
      mm    = @msgvec.to_unsafe[i]
      total = mm.msg_len.to_i
      addr  = parse_ipv4(@addr_bufs[i])
      buf   = @pkt_bufs[i]

      if @gro_enabled
        gso = read_gro_size(i)
        if gso > 0
          offset = 0
          while offset < total
            seg = Math.min(gso, total - offset)
            yield buf[offset, seg].dup, addr
            offset += gso
          end
          return
        end
      end

      # GRO disabled or no UDP_GRO cmsg present: one packet per slot.
      yield buf[0, total].dup, addr if total > 0
    end

    # Single-packet accessor for backward compatibility (non-GRO path only).
    def packet(i : Int32) : {Bytes, Socket::IPAddress}
      mm   = @msgvec.to_unsafe[i]
      size = mm.msg_len.to_i
      data = @pkt_bufs[i][0, size].dup
      addr = parse_ipv4(@addr_bufs[i])
      {data, addr}
    end

    def count : Int32
      @count
    end

    # Reset per-message metadata that the kernel overwrites on each recvmmsg call.
    private def reset_for_recv
      mmsg_ptr = @msgvec.to_unsafe
      ctrl_sz  = @gro_enabled ? CTRL_BUF_SZ.to_u64 : 0_u64
      BATCH_SIZE.times do |i|
        mm  = mmsg_ptr[i]
        hdr = mm.msg_hdr
        hdr.msg_namelen    = 28_u32
        hdr.msg_controllen = ctrl_sz
        mm.msg_hdr = hdr
        mmsg_ptr[i] = mm
      end
    end

    # Walk the cmsg chain in slot i and return gso_size from the UDP_GRO cmsg.
    # Returns 0 if no UDP_GRO cmsg is present.
    private def read_gro_size(i : Int32) : Int32
      mm       = @msgvec.to_unsafe[i]
      ctrl_ptr = mm.msg_hdr.msg_control
      ctrl_len = mm.msg_hdr.msg_controllen
      return 0 if ctrl_ptr.null? || ctrl_len < CMSG_HDR

      base   = ctrl_ptr.as(UInt8*)
      offset = 0_u64

      while offset + CMSG_HDR <= ctrl_len
        cmsg       = base + offset
        cmsg_len   = Pointer(LibC::SizeT).new(cmsg.address).value
        cmsg_level = Pointer(LibC::Int).new((cmsg + 8).address).value
        cmsg_type  = Pointer(LibC::Int).new((cmsg + 12).address).value

        if cmsg_level == SOL_UDP && cmsg_type == UDP_GRO && cmsg_len >= CMSG_HDR + 2
          return Pointer(UInt16).new((cmsg + 16).address).value.to_i
        end

        # CMSG_NXTHDR: advance by CMSG_ALIGN(cmsg_len)
        aligned = (cmsg_len + CMSG_ALGN - 1) & ~(CMSG_ALGN - 1)
        break if aligned == 0 || aligned > ctrl_len - offset
        offset += aligned
      end

      0
    end

    private def parse_ipv4(raw : Bytes) : Socket::IPAddress
      port = (raw[2].to_u16 << 8) | raw[3].to_u16
      ip   = "#{raw[4]}.#{raw[5]}.#{raw[6]}.#{raw[7]}"
      Socket::IPAddress.new(ip, port.to_i)
    rescue
      Socket::IPAddress.new("0.0.0.0", 0)
    end
  end
end
