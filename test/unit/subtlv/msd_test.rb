# frozen_string_literal: true

require_relative "../../test_helper"

# The Node and Link MSD sub-TLVs, RFC 8491 sections 2 and 3, with RFC
# 9352 section 4's SRv6 MSD types. Expected hex is our own arithmetic;
# FRR 10.7.1's Node MSD is in test/unit/pdu/lsp_srv6_test.rb.
class TestMsd < Minitest::Test
  def octets(hex) = ISIS::Octets.from_hex(hex)

  # Type 23, length 4: SRH Max SL (41, 29) 3, SRH Max H.encaps (44, 2c) 2.
  def test_node_msd
    m = ISIS::SubTlv::NodeMsd.new({ type: 41, value: 3 }, { type: 44, value: 2 })
    assert_equal "1704" "2903" "2c02", m.to_shex
    assert_equal 3, m[41]
    assert_nil m[45]
    assert_equal "Node MSD SRH Max SL 3, SRH Max H.encaps 2", m.to_s
    back = ISIS::SubTlv::NodeMsd.new(octets(m.to_shex))
    assert_equal m.to_shex, back.to_shex
    assert_equal m.to_shex, ISIS::SubTlv::NodeMsd.new(back.to_hash).to_shex
    assert_equal m.to_shex, ISIS::SubTlv::NodeMsd.new(back).to_shex
  end

  # Type 15 under TLV 22, the Base MPLS Imposition type 1, and a type
  # nobody named. A type twice is kept, in order.
  def test_link_msd
    l = ISIS::SubTlv::LinkMsd.new(octets("0f06" "010a" "fa01" "0105"))
    assert_equal [[1, 10], [250, 1], [1, 5]], l.msds
    assert_equal 10, l[1]
    assert_equal "Link MSD Base MPLS Imposition 10, type 250 1, Base MPLS Imposition 5", l.to_s
    assert_equal "0f06010afa010105", ISIS::SubTlv::LinkMsd.new(l.to_hash).to_shex
  end

  # An odd octet is a tail, replayed.
  def test_tail
    hex = "1703" "2903" "ff"
    m = ISIS::SubTlv::NodeMsd.new(octets(hex))
    assert_equal({ msds: [{ type: 41, value: 3 }], tail: "ff" }, m.to_hash)
    assert_equal hex, ISIS::SubTlv::NodeMsd.new(m.to_hash).to_shex
  end

  def test_registered
    assert_equal ISIS::SubTlv::NodeMsd, ISIS::SubTlv.class_under(242, 23)
    assert_equal ISIS::SubTlv::LinkMsd, ISIS::SubTlv.class_under(22, 15)
    assert_raises(ArgumentError) { ISIS::SubTlv::NodeMsd.new({ type: 256, value: 1 }) }
  end
end
