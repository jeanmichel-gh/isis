# frozen_string_literal: true

require_relative "../../test_helper"

# The SRv6 sub-TLVs of RFC 9352: the End SID (7.2), the End.X and LAN
# End.X SIDs (8.1, 8.2), the SID Structure sub-sub-TLV (9) and the SRv6
# Capabilities sub-TLV (2). Expected hex is our own arithmetic from those
# figures; FRR 10.7.1's are in test/unit/pdu/lsp_srv6_test.rb.
class TestSrv6SubTlvs < Minitest::Test
  def octets(hex) = ISIS::Octets.from_hex(hex)

  SID = "fc000000000100000000000000000000"
  # Type 1, length 4: block 32 (20), node 16 (10), function 16 (10),
  # argument 0.
  STRUCTURE = "0104" "20101000"
  STRUCT = { sid_structure: { block: 32, node: 16, function: 16, argument: 0 } }.freeze

  def four_ways(klass, hex)
    s = klass.new(octets(hex))
    assert_instance_of klass, s
    assert_equal hex, s.to_shex
    assert_equal hex, klass.new(s.to_hash).to_shex, "rebuilds from its hash"
    assert_equal hex, klass.new(s).to_shex, "copies"
    s
  end

  # Type 5, length 1 + 2 + 16 + 1 + 6 = 26 (1a): flags 0, behaviour 1,
  # End, the SID, Sub-sub-TLV-length 6, then the SID Structure.
  def test_end_sid
    hex = "051a" "00" "0001" + SID + "06" + STRUCTURE
    s = ISIS::SubTlv::Srv6EndSid.new(behavior: "End", sid: "fc00:0:1::", subtlvs: [STRUCT])
    assert_equal hex, s.to_shex
    four_ways(ISIS::SubTlv::Srv6EndSid, hex)
    assert_equal({ behavior: "End", sid: "fc00:0:1::", subtlvs: [STRUCT] }, s.to_hash)
    assert_equal 32, s.structure.block
    assert_equal "End SID fc00:0:1:: End; SID Structure 32/16/16/0", s.to_s
  end

  # "Flags: 1 octet. No flags are currently defined": every bit is
  # reserved, kept and echoed. No sub-sub-TLV: the length octet is 0.
  def test_end_sid_reserved_flags
    hex = "0514" "81" "0012" + SID + "00"
    s = four_ways(ISIS::SubTlv::Srv6EndSid, hex)
    assert_equal({ reserved: 0x81, behavior: "End.DT6", sid: "fc00:0:1::" }, s.to_hash)
  end

  # Type 43, length 3 + 2 + 16 + 1 + 6 = 28 (1c): B and P (0x80 | 0x20),
  # algorithm 128, weight 7, behaviour 52, End.X with NEXT-CSID.
  def test_end_x_sid
    hex = "2b1c" "a0" "80" "07" "0034" + SID + "06" + STRUCTURE
    s = ISIS::SubTlv::Srv6EndXSid.new(flags: %w[B P], algorithm: 128, weight: 7, behavior: "End.X with NEXT-CSID",
                                      sid: "fc00:0:1::", subtlvs: [STRUCT])
    assert_equal hex, s.to_shex
    four_ways(ISIS::SubTlv::Srv6EndXSid, hex)
    assert_equal({ flags: %w[B P], algorithm: 128, weight: 7, behavior: "End.X with NEXT-CSID", sid: "fc00:0:1::",
                   subtlvs: [STRUCT] }, s.to_hash)
    assert_equal "End.X SID algorithm 128 weight 7 fc00:0:1:: End.X with NEXT-CSID flags BP; SID Structure 32/16/16/0",
                 s.to_s
  end

  # The flags as section 8.1 draws them, "|B|S|P|Reserved |": B 0x80,
  # S 0x40, P 0x20, and the low five bits reserved.
  def test_end_x_flag_masks
    { "B" => 0x80, "S" => 0x40, "P" => 0x20 }.each do |letter, mask|
      assert_equal mask, ISIS::SubTlv::Srv6EndXSid.new(behavior: 5, sid: "::", flags: [letter]).flags
    end
    s = ISIS::SubTlv::Srv6EndXSid.new(octets("2b16" "5f" "00" "00" "0005" + SID + "00"))
    assert_equal %w[S], s.flag_letters
    assert_equal 0x1f, s.reserved_bits
  end

  # Type 44, length 6 + 28 = 34 (22): the neighbour's System ID first,
  # before the flags, unlike the LAN-Adj-SID.
  def test_lan_end_x_sid
    hex = "2c22" "000000000002" "40" "00" "00" "0005" + SID + "06" + STRUCTURE
    s = ISIS::SubTlv::Srv6LanEndXSid.new(neighbor: "0000.0000.0002", flags: %w[S], behavior: "End.X",
                                         sid: "fc00:0:1::", subtlvs: [STRUCT])
    assert_equal hex, s.to_shex
    four_ways(ISIS::SubTlv::Srv6LanEndXSid, hex)
    assert_equal "0000.0000.0002", s.to_hash[:neighbor]
    assert_equal "LAN End.X SID 0000.0000.0002 fc00:0:1:: End.X flags S; SID Structure 32/16/16/0", s.to_s
  end

  # The behaviour is kept as its number; the hash names it when the
  # registry has it, and gives the number when not: 125 is unassigned in
  # IANA's registry (fetched 2026-11-28).
  def test_behaviour_by_name_or_number
    s = ISIS::SubTlv::Srv6EndSid.new(behavior: 125, sid: "fc00:0:1::")
    assert_equal "0514" "00" "007d" + SID + "00", s.to_shex
    assert_equal 125, s.to_hash[:behavior]
    assert_equal "End SID fc00:0:1:: 125", s.to_s
    assert_equal 18, ISIS::SubTlv::Srv6EndSid.new(behavior: "End.DT6", sid: "::").behavior
    assert_raises(ArgumentError) { ISIS::SubTlv::Srv6EndSid.new(behavior: "End.Nope", sid: "::") }
    assert_raises(ArgumentError) { ISIS::SubTlv::Srv6EndSid.new(behavior: 0x10000, sid: "::") }
  end

  # Building never validates: End.X's behaviour in an End SID, two SID
  # Structures, a structure of 144 bits.
  def test_building_never_validates
    s = ISIS::SubTlv::Srv6EndSid.new(behavior: "End.X", sid: "fc00:0:1::",
                                     subtlvs: [STRUCT, { sid_structure: { block: 64, node: 32, function: 32, argument: 16 } }])
    back = ISIS::SubTlv::Srv6EndSid.new(octets(s.to_shex))
    assert_equal 5, back.behavior
    assert_equal [64, 144], back.subtlvs.map(&:total)
  end

  # A value too short for the fixed fields and the length octet is kept
  # whole; octets past a Sub-sub-TLV-length shorter than what was left
  # are a tail; one past it is clamped and replayed.
  def test_short_tail_and_clamp
    short = four_ways(ISIS::SubTlv::Srv6EndXSid, "2b0400000000")
    assert_equal({ short: "00000000" }, short.to_hash)
    tail = four_ways(ISIS::SubTlv::Srv6EndSid, "0516" "00" "0001" + SID + "00" + "abcd")
    assert_equal "abcd", tail.to_hash[:tail]
    clamped = ISIS::SubTlv::Srv6EndSid.new(octets("051a" "00" "0001" + SID + "09" + STRUCTURE))
    assert_equal "051a" "00" "0001" + SID + "09" + STRUCTURE, clamped.to_shex
    assert_equal 9, clamped.subtlv_length_clamped
  end

  # An unknown sub-sub-TLV stays an Unknown and replays.
  def test_unknown_sub_sub_tlv
    hex = "0517" "00" "0001" + SID + "03" + "0201ff"
    s = four_ways(ISIS::SubTlv::Srv6EndSid, hex)
    assert_instance_of ISIS::SubTlv::Unknown, s.subtlvs.first
  end

  # The four lengths, one octet each; a sum past 128 is kept. Short and
  # tail as FixedValue gives them.
  def test_sid_structure
    s = four_ways(ISIS::SubTlv::Srv6SidStructure, STRUCTURE)
    assert_equal [32, 16, 16, 0, 64], [s.block, s.node, s.function, s.argument, s.total]
    assert_equal STRUCTURE, ISIS::SubTlv::Srv6SidStructure.new(block: 32, node: 16, function: 16).to_shex
    assert_equal 255 * 4, ISIS::SubTlv::Srv6SidStructure.new(octets("0104ffffffff")).total
    four_ways(ISIS::SubTlv::Srv6SidStructure, "010520101000ee")
    four_ways(ISIS::SubTlv::Srv6SidStructure, "01022010")
  end

  # Type 25, length 2: two octets of flags, O at bit 1, 0x4000, then
  # sub-sub-TLVs, none defined, so each is an Unknown.
  def test_srv6_capabilities
    assert_equal "1902" "0000", ISIS::SubTlv::Srv6Capabilities.new.to_shex
    o = ISIS::SubTlv::Srv6Capabilities.new(flags: %w[O])
    assert_equal "1902" "4000", o.to_shex
    assert o.o?
    s = four_ways(ISIS::SubTlv::Srv6Capabilities, "1905" "c001" "0101aa")
    assert_equal({ flags: %w[O], reserved: 0x8001, subtlvs: [{ unknown: { type: 1, value: "aa" } }] }, s.to_hash)
    assert_equal "SRv6 Capabilities flags O; sub-TLV 1, 1 octets", s.to_s
    four_ways(ISIS::SubTlv::Srv6Capabilities, "190100")
  end

  # Registered under their parents: 43 and 44 under TLV 22, 25 under
  # TLV 242, 5 under TLV 27, 1 under the SID sub-TLVs' registry.
  def test_registered_under_their_parents
    assert_equal ISIS::SubTlv::Srv6EndXSid, ISIS::SubTlv.class_under(22, 43)
    assert_equal ISIS::SubTlv::Srv6LanEndXSid, ISIS::SubTlv.class_under(22, 44)
    assert_equal ISIS::SubTlv::Srv6Capabilities, ISIS::SubTlv.class_under(242, 25)
    assert_equal ISIS::SubTlv::Srv6EndSid, ISIS::SubTlv.class_under(27, 5)
    assert_equal ISIS::SubTlv::Unknown, ISIS::SubTlv.class_under(236, 5)
    assert_equal ISIS::SubTlv::Srv6SidStructure, ISIS::SubTlv.class_under(ISIS::SubTlv::Srv6Sid::REGISTRY, 1)
  end
end
