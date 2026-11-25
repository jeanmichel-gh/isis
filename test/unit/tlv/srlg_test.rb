# frozen_string_literal: true

require_relative "../../test_helper"

# TLV 138, RFC 5307 section 1.4, and TLV 238, RFC 9479 section 4.3.
# Expected hex is our own arithmetic from those layouts.
class TestTlvSrlg < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  # 7 octets of neighbour, flags 01 (numbered), the two IPv4 addresses,
  # then 10 and 20: "The length of this TLV is 16 + 4 * (number of SRLG
  # values)", 24.
  def test_srlg_numbered
    t = ISIS::Tlv::Srlg.new(neighbor: "0000.0000.0002.00", local: "10.0.12.1", remote: "10.0.12.2", srlgs: [10, 20])
    assert_equal "8a18" "00000000000200" "01" "0a000c01" "0a000c02" "0000000a" "00000014", t.to_shex
    assert t.numbered?
    assert_equal "SRLG 0000.0000.0002.00 10.0.12.1/10.0.12.2: 10, 20", t.to_s
  end

  # Flag bit clear: the two fields are link identifiers.
  def test_srlg_unnumbered
    t = ISIS::Tlv::Srlg.new(octets("8a14" "00000000000200" "00" "00000007" "00000009" "0000000a"))
    refute t.numbered?
    assert_equal({ neighbor: "0000.0000.0002.00", numbered: false, local: 7, remote: 9, srlgs: [10] }, t.to_hash)
  end

  def test_srlg_in_a_tlv_list
    list = ISIS::Tlv::List.new(octets("8a10" "00000000000200" "01" "0a000c01" "0a000c02"))
    assert_instance_of ISIS::Tlv::Srlg, list.first
    assert_empty list.first.srlgs
  end

  # Neighbour, the mask (SABM of one octet, X), the link identifiers'
  # length, the IPv4 addresses, then SRLG 10.
  def test_asla_srlg
    t = ISIS::Tlv::AslaSrlg.new(neighbor: "0000.0000.0002.00", applications: %w[X],
                                links: [{ ipv4_interface_address: "10.0.12.1" },
                                        { ipv4_neighbor_address: "10.0.12.2" }],
                                srlgs: [10])
    assert_equal "ee1b" "00000000000200" "010010" "0c" "06040a000c01" "08040a000c02" "0000000a", t.to_shex
    assert_equal %w[X], t.applications
    assert_equal [10], t.srlgs
    assert_equal [ISIS::SubTlv::Ipv4InterfaceAddress, ISIS::SubTlv::Ipv4NeighborAddress], t.links.map(&:class)
  end

  # The link identifiers are read from TLV 238's own registry (Table 2):
  # 4, 6, 8, 12 and 13. An Adj-SID's 31 stays unknown there.
  def test_asla_srlg_registry
    hex = "ee1f" "00000000000200" "0000" "11" "04080000000700000009" "1f053000003a98" "0000000a"
    t = ISIS::Tlv::AslaSrlg.new(octets(hex))
    assert_equal [ISIS::SubTlv::LinkIdentifiers, ISIS::SubTlv::Unknown], t.links.map(&:class)
  end

  # Cut before the SRLGs could start: kept whole.
  def test_asla_srlg_short
    t = ISIS::Tlv::AslaSrlg.new(octets("ee0b" "00000000000200" "0000" "09" "00"))
    assert_equal({ short: "00000000000200000009" "00" }, t.to_hash)
    assert_equal "ee0b" "00000000000200" "0000" "09" "00", t.to_shex
  end
end
