# frozen_string_literal: true

require_relative "../test_helper"

# The catalog's packets (ISIS::Fault::PACKETS) as they are built: each
# names itself by its UDP source port, carries the labels its roles ask
# for with the TTL on top, and has a sound IPv4 header.
# test/interop/kernel_ti_lfa_test.rb sends them at a PLR.
class TestFaultPacket < Minitest::Test
  LABELS = { destination: 17_003, adj: 15_001, unknown: 99_999 }.freeze

  def build(name) = ISIS::Fault.packet(name, src: "10.9.0.2", dst: "10.255.0.3", labels: LABELS)

  # The IPv4 header and UDP source port after any labels.
  def ip_of(type, octets)
    return [[], octets] if type == 0x0800

    stack = ISIS::Mpls::LabelStack.new(ISIS::Octets.new(octets.dup))
    [stack.to_hash[:entries], octets.byteslice((4 * stack.labels.size)..)]
  end

  def test_each_packet_as_its_entry_says
    ISIS::Fault.packets.each do |e|
      type, octets = build(e[:name])
      entries, ip = ip_of(type, octets)
      kind, *roles = Array(e[:send])
      assert_equal(kind == :ip ? 0x0800 : 0x8847, type, e[:name])
      assert_equal roles.map { LABELS.fetch(_1) }, entries.map { _1[:label] }, e[:name]
      assert_equal [true], entries.last(1).map { _1[:bottom] } unless entries.empty?
      assert_equal e[:ttl], kind == :ip ? ip.getbyte(8) : entries.first[:ttl], e[:name]
      assert_equal e[:port], ip.byteslice(20, 2).unpack1("n")
      assert_equal e[:name], ISIS::Fault.packet_named_by(e[:port])
      assert_equal e[:name].to_s, ip.byteslice(28..)
    end
  end

  # The header's one's complement sum is all ones when its checksum is
  # right, and its total length is the packet's.
  def test_the_ipv4_header_is_sound
    ip = ISIS::Fault.ipv4_udp(src: "10.9.0.2", dst: "10.255.0.3", ttl: 7, port: 40_000, payload: "x")
    sum = ip.byteslice(0, 20).unpack("n*").sum
    sum = (sum & 0xffff) + (sum >> 16) while sum > 0xffff
    assert_equal 0xffff, sum
    assert_equal ip.bytesize, ip.byteslice(2, 2).unpack1("n")
    assert_equal [17, 7], [ip.getbyte(9), ip.getbyte(8)]
    assert_equal %w[10.9.0.2 10.255.0.3], [ip.byteslice(12, 4), ip.byteslice(16, 4)].map { IPAddr.new_ntoh(_1).to_s }
  end

  def test_every_port_is_its_own
    ports = ISIS::Fault.packets.map { _1[:port] }
    assert_equal ports.uniq, ports
    assert_nil ISIS::Fault.packet_named_by(9)
  end

  def test_expect_is_the_repair_or_a_record
    assert(ISIS::Fault.packets.all? { %i[repair record].include?(_1[:expect]) })
    assert(ISIS::Fault.packets.all? { _1[:rfc].start_with?("RFC 9855") })
  end

  def test_an_unknown_packet
    e = assert_raises(ArgumentError) { ISIS::Fault.packet_entry(:nope) }
    assert_match(/packet_ip/, e.message)
  end
end
