# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/topology_lab"

# The catalog's packets at the PLR (ISIS::Fault::PACKETS), on real
# routers in network namespaces (test/support/topology_lab.rb): the
# topology ti_lfa_pq_node, isisd everywhere, the PLR S installing its
# routes, label routes and backups in the kernel, and a host H behind S.
#
# S's isisd is stopped (SIGSTOP) before the link to F loses carrier, so
# what follows is the kernel's alone, as in the first milliseconds of a
# failure, before isisd reconverges. H sends every packet; A, the
# repair's first hop, and H itself capture what comes of each.
#
# An entry whose expect is :repair must reach A with the repair list,
# then the destination's label in Q's SRGB (RFC 9855 6.1, 7.1), unless
# GAPS names why not; a :record entry must do what RECORDED says, as
# Linux did here.
#
# Root, iproute2, FRR's paths as FrrLab checks them, and the MPLS
# modules (mpls_router, mpls_iptunnel). Runs only with ISIS_FRR=1.
class TestKernelTiLfa < Minitest::Test
  TOPOLOGY = :ti_lfa_pq_node

  # Where isisd falls short of the RFC, and why. A packet named here must
  # be dropped; once the gap closes, the test fails and says so.
  GAPS = {
    packet_prefix_sid: "a label route switches only when isisd replaces it; the kernel has no backup for it " \
                       "(routescope docs/design/ti-lfa.md, step 2c)"
  }.freeze

  # What Linux did with each :record entry, measured 2026-11-22 on 7.0:
  # where the packet went and what came back to H.
  RECORDED = {
    packet_ip_ttl_1: { at_a: nil, back: [[11, 0], :packet_ip_ttl_1] },
    packet_mpls_ttl_1: { at_a: nil, back: nil },
    packet_unknown_label: { at_a: nil, back: nil },
    packet_adj_sid: { at_a: nil, back: nil }
  }.freeze

  def setup
    ok, why = FrrLab.available?
    unless ok && File.read("/proc/modules").include?("mpls_iptunnel")
      why ||= "needs the MPLS modules: sudo modprobe mpls_router mpls_iptunnel"
      flunk "FRR interop asked for and cannot run: #{why}" if ENV["ISIS_FRR"] == "1"
      skip why
    end
  end

  def teardown
    @lab&.stop
  end

  def destination = @lab.destination_prefix.split("/").first

  def labels
    adj = @lab.isisd("S", "show.segment_routing")["adj_sids"].find { _1["neighbor"] == "F" && _1["family"] == "ipv4" }
    { destination: @lab.srgb("S") + @lab.number("D"), adj: adj.fetch("label"), unknown: 99_999 }
  end

  # Stops S's isisd, takes S-F's carrier, waits for the kernel to take
  # the backup, sends every packet from H and returns, per entry, what
  # reached A and what came back to H.
  def during_repair
    @lab = TopologyLab.new("kp#{Process.pid % 1000}", TOPOLOGY, sender: true, forwarding: true).start
    @lab.settled_repair(180)
    frames = ISIS::Fault.packet_names.map { ISIS::Fault.packet(_1, src: "10.9.0.2", dst: destination, labels: labels) }
    @lab.freeze("S")
    @lab.far_end_down("S", "F")
    assert @lab.wait_for(5) { @lab.route_get("S", destination).include?("dev toA") }, "the kernel takes the backup"
    at_h = nil
    at_a = @lab.capture(@lab.ns("A"), "toS") { at_h = @lab.capture(@lab.sender_ns, "toS") { @lab.send_from_sender(frames) } }
    at_a = at_a.filter_map { TopologyLab.read_frame(*_1) }.select { _1[:packet] }
    back = at_h.filter_map { TopologyLab.read_frame(*_1) }.select { _1[:icmp] }
    ISIS::Fault.packet_names.to_h do |name|
      a = at_a.find { _1[:packet] == name }
      b = back.find { _1[:quotes] == name }
      [name, { at_a: a && { segments: @lab.segments_of(a[:labels], "A"), ttl: a[:ttl] }, back: b && [b[:icmp], name] }]
    end
  ensure
    @lab&.thaw("S")
  end

  # Every packet, in one failure: the repair for those the RFC asks it
  # of, and the rest as recorded.
  def test_the_packets_at_the_plr_during_a_repair
    got = during_repair
    e = ISIS::Fault.topology(TOPOLOGY)[:expect]
    repair = e[:segments] + (e[:q] == "D" ? [] : [[:node, "D"]])
    ISIS::Fault.packets.each do |p|
      name = p[:name]
      if p[:expect] == :repair && !GAPS.key?(name)
        assert_equal({ segments: repair, ttl: 63 }, got[name][:at_a], "#{name}: the repair, RFC 9855 6.1 and 7.1")
      elsif p[:expect] == :repair
        assert_nil got[name][:at_a], "#{name} reached A: has the gap closed? #{GAPS[name]}"
      else
        assert_equal RECORDED.fetch(name), got[name], "#{name}, as recorded"
      end
    end
  end

  def test_every_packet_is_expected_or_recorded
    ISIS::Fault.packets.each do |p|
      known = p[:expect] == :repair || RECORDED.key?(p[:name])
      assert known, "#{p[:name]} has neither the RFC's repair nor a record"
    end
  end
end
