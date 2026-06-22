# SO_TXTIME kernel pacing: socket option that lets fq qdisc release each
# datagram at a specified TAI timestamp instead of immediately.
# Requires kernel >= 4.19 and qdisc `fq` (not `fq_codel`).
lib LibSys
  SO_TXTIME  = 61
  SCM_TXTIME = 61

  # Passed to setsockopt(SO_TXTIME)
  struct SockTxtime
    clockid : LibC::Int  # CLOCK_TAI = 11
    flags : LibC::UInt   # 0 for normal; 1 = TXTIME_DEADLINE_MODE; 2 = TXTIME_REPORT_ERRORS
  end
end
