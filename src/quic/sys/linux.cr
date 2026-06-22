# Linux syscall bindings for high-performance UDP I/O.
# sendmmsg(2): batch N UDP datagrams in one syscall (Linux 3.0+, kernel NR 307).
lib LibSys
  # UDP socket options (kernel/include/uapi/linux/udp.h)
  UDP_SEGMENT = 103 # cmsg: segment size for GSO fragmentation
  UDP_GRO     = 104 # socket option: receive-side coalescing

  # IPPROTO_UDP = SOL_UDP = 17 (used as cmsg_level for UDP_SEGMENT)
  IPPROTO_UDP = 17

  struct Iovec
    iov_base : Void*
    iov_len : LibC::SizeT
  end

  # struct msghdr — C ABI on x86-64: sizeof = 56
  # Offsets: name=0, namelen=8, [pad=12], iov=16, iovlen=24,
  #          control=32, controllen=40, flags=48, [pad=52]
  struct Msghdr
    msg_name : Void*
    msg_namelen : LibC::UInt
    msg_iov : LibSys::Iovec*
    msg_iovlen : LibC::SizeT
    msg_control : Void*
    msg_controllen : LibC::SizeT
    msg_flags : LibC::Int
  end

  # struct mmsghdr — sizeof = 64 (56 + 4 + 4 pad)
  struct Mmsghdr
    msg_hdr : LibSys::Msghdr
    msg_len : LibC::UInt
  end

  fun sendmmsg(sockfd : LibC::Int, msgvec : LibSys::Mmsghdr*, vlen : LibC::UInt, flags : LibC::Int) : LibC::Int
  fun recvmmsg(sockfd : LibC::Int, msgvec : LibSys::Mmsghdr*, vlen : LibC::UInt, flags : LibC::Int, timeout : Void*) : LibC::Int
end
