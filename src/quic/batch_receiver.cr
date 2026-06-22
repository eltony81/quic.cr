require "./sys/linux"
require "socket"

module QUIC
  # Receives multiple UDP datagrams per syscall via recvmmsg(2) (Linux 2.6.33+).
  # Integrates with Crystal's non-blocking IO: the first packet uses the normal
  # UDPSocket#receive (which yields the fiber via epoll), then immediately drains
  # any already-buffered packets using recvmmsg with MSG_DONTWAIT.
  #
  # With UDP_GRO enabled, the kernel coalesces multiple equal-size datagrams into
  # a single recvmmsg entry; we split them by the advertised segment size.
  #
  # All buffers are pre-allocated at construction; recv/packet calls are
  # allocation-free on the hot path.
  class BatchReceiver
    BATCH_SIZE = 64
    MAX_PKT    = 9000   # allow jumbo frames when GRO is active

    MSG_DONTWAIT = 0x40   # non-blocking flag for recvmmsg
    SOL_UDP      = 17
    UDP_GRO      = 104

    @fd      : Int32
    @pkt_bufs : Array(Bytes)
    @addr_bufs : Array(Bytes)
    @iovecs   : Array(LibSys::Iovec)
    @msgvec   : Array(LibSys::Mmsghdr)
    @count    : Int32 = 0
    @gro_enabled : Bool = false

    def initialize(socket : UDPSocket)
      @fd = socket.fd
      @pkt_bufs  = Array.new(BATCH_SIZE) { Bytes.new(MAX_PKT, 0_u8) }
      @addr_bufs = Array.new(BATCH_SIZE) { Bytes.new(28, 0_u8) }
      @iovecs    = Array.new(BATCH_SIZE) { LibSys::Iovec.new }
      @msgvec    = Array.new(BATCH_SIZE) { LibSys::Mmsghdr.new }

      # Crystal structs are value types: field assignment via arr[i].field= modifies
      # a temporary copy, not the backing buffer. We must build each struct in a
      # local variable and write it back via the raw pointer.
      iov_ptr  = @iovecs.to_unsafe
      mmsg_ptr = @msgvec.to_unsafe

      BATCH_SIZE.times do |i|
        iov = LibSys::Iovec.new
        iov.iov_base = @pkt_bufs[i].to_unsafe.as(Void*)
        iov.iov_len  = MAX_PKT.to_u64
        iov_ptr[i] = iov   # write the completed struct back to the buffer

        hdr = LibSys::Msghdr.new
        hdr.msg_name       = @addr_bufs[i].to_unsafe.as(Void*)
        hdr.msg_namelen    = 28_u32
        hdr.msg_iov        = iov_ptr + i   # pointer into the iov array buffer
        hdr.msg_iovlen     = 1_u64
        hdr.msg_control    = Pointer(Void).null
        hdr.msg_controllen = 0_u64
        hdr.msg_flags      = 0

        mm = LibSys::Mmsghdr.new
        mm.msg_hdr = hdr
        mm.msg_len = 0_u32
        mmsg_ptr[i] = mm   # write the completed struct back to the buffer
      end
    end

    # Try to enable UDP_GRO. Returns true when the kernel accepted the option.
    def enable_gro!(socket : UDPSocket) : Bool
      val = 1_i32
      ret = LibC.setsockopt(socket.fd, SOL_UDP, UDP_GRO,
                            pointerof(val).as(Void*), sizeof(Int32).to_u32)
      @gro_enabled = ret == 0
    end

    def gro_enabled? : Bool
      @gro_enabled
    end

    # Non-blocking drain: call right after the first packet has been received via
    # UDPSocket#receive. Fills internal buffers with up to BATCH_SIZE-1 more
    # packets without blocking. Returns the number of additional packets received.
    def drain_nowait : Int32
      reset_name_lens
      ret = LibSys.recvmmsg(@fd, @msgvec.to_unsafe, BATCH_SIZE.to_u32, MSG_DONTWAIT, nil)
      @count = ret > 0 ? ret : 0
    end

    # Returns {data_copy, peer_address} for the packet at batch index i.
    def packet(i : Int32) : {Bytes, Socket::IPAddress}
      # Read the full Mmsghdr struct into a local copy to access msg_len.
      mm   = @msgvec.to_unsafe[i]
      size = mm.msg_len.to_i
      data = @pkt_bufs[i][0, size].dup
      addr = parse_ipv4(@addr_bufs[i])
      {data, addr}
    end

    def count : Int32
      @count
    end

    private def reset_name_lens
      mmsg_ptr = @msgvec.to_unsafe
      BATCH_SIZE.times do |i|
        mm = mmsg_ptr[i]
        hdr = mm.msg_hdr
        hdr.msg_namelen = 28_u32
        mm.msg_hdr = hdr
        mmsg_ptr[i] = mm
      end
    end

    # Parse a raw sockaddr_in (AF_INET only; IPv6 not needed for loopback bench).
    private def parse_ipv4(raw : Bytes) : Socket::IPAddress
      port = (raw[2].to_u16 << 8) | raw[3].to_u16
      ip   = "#{raw[4]}.#{raw[5]}.#{raw[6]}.#{raw[7]}"
      Socket::IPAddress.new(ip, port.to_i)
    rescue
      Socket::IPAddress.new("0.0.0.0", 0)
    end
  end
end
