require "./spec_helper"
require "socket"

describe "ECN (RFC 9000 §13.4 + RFC 9002 §7.6)" do
  it "ECT(0) codepoint is 0x02 (lower 2 bits of IP TOS)" do
    ect0 = 0x02
    (ect0 & 0x03).should eq(2)
  end

  it "LibSys::IPPROTO_IP is 0 and LibSys::IP_TOS is 1 (POSIX)" do
    LibSys::IPPROTO_IP.should eq(0)
    LibSys::IP_TOS.should eq(1)
  end

  it "setsockopt(IP_TOS=ECT(0)) succeeds on a local UDP socket" do
    udp = UDPSocket.new
    udp.bind("127.0.0.1", 0)
    tos = 2  # ECT(0)
    ret = LibC.setsockopt(udp.fd, LibSys::IPPROTO_IP, LibSys::IP_TOS, pointerof(tos).as(Void*), sizeof(Int32).to_u32)
    ret.should eq(0)
    udp.close
  end

  it "Recovery reduces cwnd on new ECN-CE marks from ACK frame" do
    r   = QUIC::Recovery.new
    # Prime the recovery with a sent packet and an RTT sample
    r.on_packet_sent(0_u64, 1200, [] of QUIC::Frame, true, 2)
    ack0 = QUIC::AckFrame.new(0_u64, 0_u64, 0_u64)
    r.on_ack_received(ack0, Time.local, 2)

    cwnd_before = r.congestion_window

    # ACK with ECN-CE mark (ecn_ce=1) — triggers congestion halving
    r.on_packet_sent(1_u64, 1200, [] of QUIC::Frame, true, 2)
    ack_ecn = QUIC::AckFrame.new(1_u64, 0_u64, 0_u64, ecn_ce: 1_u64, has_ecn: true)
    r.on_ack_received(ack_ecn, Time.local, 2)

    r.congestion_window.should be < cwnd_before
  end
end
