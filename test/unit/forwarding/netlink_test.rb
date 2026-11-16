# frozen_string_literal: true

require_relative "../../test_helper"

# The netlink messages, against hex worked out by hand from the layouts in
# linux/netlink.h and linux/rtnetlink.h, in little-endian order: our own
# arithmetic, not a capture. The socket is a fake that answers as the
# kernel does, so these run without privilege.
class TestForwardingNetlink < Minitest::Test
  # A socket that keeps what it is sent and replies from a queue.
  class FakeSocket
    attr_reader :sent

    def initialize
      @sent = []
      @replies = []
    end

    def queue(*messages)
      @replies << messages.join.b
    end

    def send(message, _flags)
      @sent << message
      yield message if block_given?
      message.bytesize
    end

    def recv(_max)
      @replies.shift || raise("nothing queued")
    end

    def close; end
  end

  def setup
    skip "netlink is host byte order; these expectations are little-endian" unless [1].pack("S") == "\x01\x00"
    @clock = ISIS::Runtime::ManualClock.new
    @log = ISIS::Runtime::Log.new(clock: @clock, logger: TestLogs.logger(@clock))
    @socket = FakeSocket.new
    @nl = ISIS::Forwarding::Netlink.new(log: @log, socket: @socket, interfaces: { "eth0-l1" => "eth0" })
    @nl.define_singleton_method(:ifindex) { |name| { "eth0" => 3, "eth1" => 4 }.fetch(name) }
  end

  def hex(octets) = octets.unpack1("H*")

  def adjacency(circuit, address, address6 = nil)
    ISIS::Spf::Adjacency.new(circuit: circuit, neighbor: "\x00\x00\x00\x00\x00\x02".b, circuit_id: 1,
                             address: address, address6: address6)
  end

  # An acknowledgement: nlmsghdr type NLMSG_ERROR, then the s32 error, then
  # the header of the request. 16 + 4 + 16 = 36.
  def ack(sequence, code = 0)
    [36, 2, 0, sequence, 0].pack("LSSLL") + [code].pack("l") + [0, 0, 0, sequence, 0].pack("LSSLL")
  end

  # nlmsghdr: 44000000 length 68, 1800 RTM_NEWROUTE, 0505 REQUEST | ACK |
  # REPLACE | CREATE, 01000000 sequence 1, 00000000 port.
  # rtmsg: 02 AF_INET, 20 /32, 00 00, fe main, bb RTPROT_ISIS 187, 00
  # universe, 01 unicast, 00000000 flags.
  # Then RTA_TABLE 254, RTA_DST 192.0.2.2, RTA_PRIORITY 20, RTA_OIF 3,
  # RTA_GATEWAY 10.0.12.2, each 0800 type value.
  def test_one_next_hop
    m = @nl.new_message(:ipv4, "192.0.2.2/32", [[3, "10.0.12.2"]])
    assert_equal "44000000" "1800" "0505" "01000000" "00000000" \
                 "022000" "00" "fe" "bb" "00" "01" "00000000" \
                 "08000f00fe000000" "08000100c0000202" "0800060014000000" \
                 "0800040003000000" "080005000a000c02", hex(m)
  end

  # RTA_MULTIPATH, 2400 0900: 36 octets, two rtnexthops of 16 each, 1000
  # length, 00 flags, 00 hops, ifindex, then RTA_GATEWAY. Length 88.
  def test_several_next_hops
    m = @nl.new_message(:ipv4, "192.0.2.0/24", [[3, "10.0.12.2"], [4, "10.0.13.3"]])
    assert_equal "58000000" "1800" "0505" "01000000" "00000000" \
                 "021800" "00" "fe" "bb" "00" "01" "00000000" \
                 "08000f00fe000000" "08000100c0000200" "0800060014000000" \
                 "24000900" "1000" "00" "00" "03000000" "080005000a000c02" \
                 "1000" "00" "00" "04000000" "080005000a000d03", hex(m)
  end

  # RTM_DELROUTE, 1900, flags 0500 REQUEST | ACK. rtmsg 0a AF_INET6, 80
  # /128, scope ff RT_SCOPE_NOWHERE and type 00, which match any. RTA_DST
  # is 1400 0100 and sixteen octets. Length 64.
  def test_a_withdrawal
    m = @nl.delete_message(:ipv6, "2001:db8::2/128")
    assert_equal "40000000" "1900" "0500" "01000000" "00000000" \
                 "0a8000" "00" "fe" "bb" "ff" "00" "00000000" \
                 "08000f00fe000000" "1400010020010db8000000000000000000000002" "0800060014000000", hex(m)
  end

  # Each message takes the next sequence number, so an ack matches it.
  def test_sequence_numbers_advance
    @nl.delete_message(:ipv4, "192.0.2.2/32")
    assert_equal 2, @nl.delete_message(:ipv4, "192.0.2.2/32").unpack1("@8L")
  end

  def test_apply_installs_through_the_mapped_interface_and_reads_the_ack
    @socket.queue(ack(1))
    route = ISIS::Spf::Route.new("192.0.2.2/32", 11, [adjacency("eth0-l1", "10.0.12.2")])
    assert @nl.apply(ISIS::Forwarding::Operation.new(kind: :install, route: route))
    assert_equal hex(@nl.dup.tap { |n| n.instance_variable_set(:@sequence, 0) }
                        .new_message(:ipv4, "192.0.2.2/32", [[3, "10.0.12.2"]])), hex(@socket.sent.first)
  end

  # An IPv6 route goes through the neighbour's link-local address, and an
  # adjacency with none for the family is left out. RTA_GATEWAY is 1400
  # 0500: twenty octets.
  def test_apply_uses_the_familys_next_hop
    @socket.queue(ack(1))
    route = ISIS::Spf::Route.new("2001:db8::2/128", 11,
                                 [adjacency("eth0", "10.0.12.2", "fe80::2"), adjacency("eth1", "10.0.13.3")])
    assert @nl.apply(ISIS::Forwarding::Operation.new(kind: :replace, route: route))
    gateway = IPAddr.new("fe80::2").hton.unpack1("H*")
    assert_match(/0800040003000000 1400 0500 #{gateway}\z/x, hex(@socket.sent.first))
    refute_match(/24000900/, hex(@socket.sent.first))
  end

  def test_no_next_hop_in_the_family_installs_nothing
    route = ISIS::Spf::Route.new("2001:db8::2/128", 11, [adjacency("eth0", "10.0.12.2")])
    refute @nl.apply(ISIS::Forwarding::Operation.new(kind: :install, route: route))
    assert_empty @socket.sent
  end

  # A refusal is logged with its errno and returns false; nothing raises.
  def test_a_refusal_is_logged_and_counted
    @socket.queue(ack(1, -3))
    route = ISIS::Spf::Route.new("192.0.2.2/32", 11, [adjacency("eth0", "10.0.12.2")])
    refute @nl.apply(ISIS::Forwarding::Operation.new(kind: :withdraw, route: route))
    assert_equal 1, @nl.errors
    assert_match(/ESRCH \(3\)/, @log.events.last.message)
  end

  # A reply for another sequence is not this request's answer.
  def test_an_ack_for_another_request_is_skipped
    @socket.queue(ack(7, -1), ack(1))
    route = ISIS::Spf::Route.new("192.0.2.2/32", 11, [adjacency("eth0", "10.0.12.2")])
    assert @nl.apply(ISIS::Forwarding::Operation.new(kind: :withdraw, route: route))
    assert_equal ISIS::Forwarding::Netlink::RTM_DELROUTE, @socket.sent.first.unpack1("@4S")
  end

  # A dumped route: nlmsghdr type RTM_NEWROUTE, an rtmsg, then attributes.
  def dumped(sequence, prefix, len, protocol, priority, scope: 0, type: 1)
    addr = IPAddr.new(prefix).hton
    body = [2, len, 0, 0, 254, protocol, scope, type, 0].pack("C8L") +
           [8, 1].pack("SS") + addr + [8, 6, priority].pack("SSL")
    [16 + body.bytesize, 24, 2, sequence, 0].pack("LSSLL") + body
  end

  # Flush removes this adapter's routes, its protocol and its priority,
  # and leaves the rest: another protocol, or the other level's priority.
  def test_flush_removes_only_its_own_routes
    done = [20, 3, 2, 1, 0].pack("LSSLL") + [0].pack("l")
    @socket.queue(dumped(1, "192.0.2.2", 32, 187, 20), dumped(1, "192.0.2.3", 32, 186, 20),
                  dumped(1, "192.0.2.4", 32, 187, 21))
    @socket.queue(done)
    @socket.queue(ack(2))
    assert_equal 1, @nl.flush
    assert_equal 2, @socket.sent.size
    assert_equal hex(ISIS::Forwarding::Netlink.new(log: @log, socket: nil).tap { |n| n.instance_variable_set(:@sequence, 1) }
                        .delete_message(:ipv4, "192.0.2.2/32")), hex(@socket.sent.last)
  end

  # The kernel's routes for Redistribution, scope and type included: here a
  # connected subnet, protocol kernel 2, scope link 253.
  def test_routes_reads_the_table
    done = [20, 3, 2, 1, 0].pack("LSSLL") + [0].pack("l")
    @socket.queue(dumped(1, "10.0.12.0", 24, 2, 0, scope: 253), dumped(1, "198.18.7.0", 24, 3, 0, type: 6))
    @socket.queue(done)
    assert_equal [{ family: :ipv4, prefix: "10.0.12.0/24", table: 254, protocol: 2, scope: 253, type: 1, priority: 0 },
                  { family: :ipv4, prefix: "198.18.7.0/24", table: 254, protocol: 3, scope: 0, type: 6, priority: 0 }],
                 @nl.routes
  end

  # --- MPLS. The message bodies (after the 16 octet nlmsghdr) are the ones
  # iproute2 6.19 sent, captured with strace in a network namespace on the
  # lab VM, 2026-11-16, for ifindex 2 and 3 (d0, d1) and 1 (lo):
  #
  #   ip -M route add 100 as 200 via inet 10.0.0.2 dev d0 proto 187
  #
  # Only the header differs: iproute2 asks NLM_F_EXCL, isisd NLM_F_REPLACE.
  # rtmsg: 1c AF_MPLS 28, 14 a 20 bit destination, fe main, bb protocol 187,
  # 00 universe, 01 unicast. RTA_DST 0800 0100 00064100, 100 << 12 with
  # the bottom-of-stack bit 0x100; RTA_NEWDST 0800 1300; RTA_VIA 0a00 1200,
  # the family 0200 (AF_INET, host order) and the address, padded; RTA_OIF.
  RTMSG_MPLS = "1c140000febb000100000000"

  def body(m) = hex(m.byteslice(16..))

  def test_a_label_swap_is_iproute2s
    m = @nl.label_message(100, [[2, :ipv4, "10.0.0.2", 200]])
    assert_equal "1800" "0505", hex(m.byteslice(4, 4))
    assert_equal RTMSG_MPLS + "0800010000064100" "08001300000c8100" "0a00120002000a0000020000" "0800040002000000", body(m)
  end

  # ip -M route add 101 via inet 10.0.0.2 dev d0: a pop, no RTA_NEWDST.
  def test_a_pop_is_iproute2s
    m = @nl.label_message(101, [[2, :ipv4, "10.0.0.2", nil]])
    assert_equal RTMSG_MPLS + "0800010000065100" "0a00120002000a0000020000" "0800040002000000", body(m)
  end

  # ip -M route add 102 dev lo: pop and look the packet up again.
  def test_a_pop_to_lookup_is_iproute2s
    m = @nl.label_message(102, [[1, nil, nil, nil]])
    assert_equal RTMSG_MPLS + "0800010000066100" "0800040001000000", body(m)
  end

  # ip -M route add 103 nexthop as 300 via inet 10.0.0.2 dev d0 nexthop as
  # 301 via inet 10.0.1.2 dev d1: RTA_MULTIPATH 3c00 0900, two rtnexthops
  # of 1c00 each, then their RTA_NEWDST and RTA_VIA.
  def test_a_multipath_label_is_iproute2s
    m = @nl.label_message(103, [[2, :ipv4, "10.0.0.2", 300], [3, :ipv4, "10.0.1.2", 301]])
    assert_equal RTMSG_MPLS + "0800010000067100" "3c000900"                "1c000000" "02000000" "080013000012c100" "0a00120002000a0000020000"                "1c000000" "03000000" "080013000012d100" "0a00120002000a0001020000", body(m)
  end

  # ip -M route del 100 proto 187, the whole message: 2400 length 36,
  # 1900 RTM_DELROUTE, 0500 REQUEST | ACK.
  def test_a_label_withdrawal_is_iproute2s
    assert_equal "24000000" "1900" "0500" "01000000" "00000000" + RTMSG_MPLS + "0800010000064100",
                 hex(@nl.label_delete_message(100))
  end

  # ip route add 192.0.2.4/32 encap mpls 18004 via 10.0.0.2 dev d0: RTA_ENCAP
  # 0c00 1680, type 22 with NLA_F_NESTED, holding MPLS_IPTUNNEL_DST 0800
  # 0100 04654100 (18004 << 12 | 0x100); then RTA_ENCAP_TYPE 0600 1500,
  # 0100 LWTUNNEL_ENCAP_MPLS, padded. iproute2 sends them in that order.
  ENCAP_18004 = "0c001680080001000465410006001500" "01000000"

  def test_an_ip_route_pushes_a_label
    m = @nl.new_message(:ipv4, "192.0.2.4/32", [[3, "10.0.12.2", 18_004]])
    assert_includes body(m), "0800040003000000" "080005000a000c02" + ENCAP_18004
    refute_includes hex(@nl.new_message(:ipv4, "192.0.2.4/32", [[3, "10.0.12.2"]])), "1680"
  end

  # In a multipath route each next hop carries its own, as iproute2 writes
  # nexthop encap mpls 400 via ... nexthop via ...
  def test_a_multipath_ip_route_pushes_per_next_hop
    m = @nl.new_message(:ipv4, "192.0.2.5/32", [[3, "10.0.12.2", 400], [4, "10.0.13.3", nil]])
    assert_includes body(m), "2400" "0000" "03000000" "080005000a000c02" "0c00168008000100" "00190100" "0600150001000000"
    assert_includes body(m), "1000" "0000" "04000000" "080005000a000d03"
  end

  def entry(label, op, hops) = ISIS::Spf::Labels::Entry.new(label, op, :prefix_sid, "192.0.2.4/32", hops)

  # A label operation goes by the next hop's IPv4 address, through the
  # mapped interface; implicit null is a pop.
  def test_apply_installs_a_label
    @socket.queue(ack(1))
    op = ISIS::Forwarding::LabelOperation.new(kind: :install, entry: entry(17_004, :swap, [[adjacency("eth0-l1", "10.0.12.2"), 18_004]]))
    assert @nl.apply(op)
    expected = ISIS::Forwarding::Netlink.new(log: @log, socket: nil).label_message(17_004, [[3, :ipv4, "10.0.12.2", 18_004]])
    assert_equal body(expected), body(@socket.sent.first)
    @socket.queue(ack(2))
    pop = ISIS::Forwarding::LabelOperation.new(kind: :install, entry: entry(17_002, :php, [[adjacency("eth1", "10.0.13.3"), 3]]))
    assert @nl.apply(pop)
    refute_includes hex(@socket.sent.last), "1300", "no RTA_NEWDST"
  end

  # An IP route operation pushes the label its labels map gives the hop.
  def test_apply_pushes_the_routes_label
    @socket.queue(ack(1))
    a = adjacency("eth0-l1", "10.0.12.2")
    route = ISIS::Spf::Route.new("192.0.2.4/32", 30, [a])
    labels = { ["eth0-l1", a.neighbor.b] => 18_004 }
    assert @nl.apply(ISIS::Forwarding::Operation.new(kind: :install, route: route, labels: labels))
    assert_includes hex(@socket.sent.first), ENCAP_18004
  end

  def mpls_dumped(sequence, label, protocol)
    body = [28, 20, 0, 0, 254, protocol, 0, 1, 0].pack("C8L") + [8, 1].pack("SS") + [(label << 12) | 0x100].pack("N")
    [16 + body.bytesize, 24, 2, sequence, 0].pack("LSSLL") + body
  end

  # The kernel's label routes are not IP routes for Redistribution, and
  # flush_labels removes this protocol's, and only them.
  def test_label_routes_in_a_dump
    done = [20, 3, 2, 1, 0].pack("LSSLL") + [0].pack("l")
    @socket.queue(dumped(1, "10.0.12.0", 24, 2, 0, scope: 253), mpls_dumped(1, 17_004, 187))
    @socket.queue(done)
    assert_equal ["10.0.12.0/24"], @nl.routes.map { _1[:prefix] }
    @socket.queue(mpls_dumped(2, 17_004, 187), mpls_dumped(2, 16_003, 186))
    @socket.queue([20, 3, 2, 2, 0].pack("LSSLL") + [0].pack("l"))
    @socket.queue(ack(3))
    assert_equal 1, @nl.flush_labels
    assert_equal "080001000426c100", hex(@socket.sent.last)[-16..], "17004 is 0x426c"
  end
end
