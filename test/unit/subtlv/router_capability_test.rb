# frozen_string_literal: true

require_relative "../../test_helper"

# The sub-TLVs of TLV 242 that RFC 8667 section 3 defines, SR-Capabilities,
# SR-Algorithm and SR Local Block, and the SID/Label sub-TLV of section 2.3
# their descriptors carry. Expected hex is our own arithmetic from the
# figures.
class TestSubTlvRouterCapability < Minitest::Test
  def octets(hex)
    ISIS::Octets.from_hex(hex)
  end

  def replays(klass, hex)
    s = klass.new(octets(hex))
    assert_equal hex, s.to_shex, "#{klass} replays"
    assert_equal hex, klass.new(s.to_hash).to_shex, "#{klass} rebuilds from its hash"
    assert_equal hex, klass.new(s).to_shex, "#{klass} copies"
    s
  end

  # SID/Label, section 2.3: "If the length is set to 3, then the 20
  # rightmost bits represent an MPLS label. If the length is set to 4, then
  # the value is a 32-bit index." 01 type, 03 length, 003e80 is 16000.
  def test_sid_label
    assert_equal "0103003e80", ISIS::SubTlv::SidLabel.new(label: 16000).to_shex
    assert_equal "010400000001", ISIS::SubTlv::SidLabel.new(index: 1).to_shex
    assert_equal({ label: 16000 }, replays(ISIS::SubTlv::SidLabel, "0103003e80").to_hash)
    assert_equal({ index: 1 }, replays(ISIS::SubTlv::SidLabel, "010400000001").to_hash)
  end

  # Only the 20 rightmost bits are the label. The four above it are kept.
  def test_label_high_bits_replay
    s = replays(ISIS::SubTlv::SidLabel, "0103f03e80")
    assert_equal({ label: 16000, label_high: 15 }, s.to_hash)
  end

  def test_a_label_too_wide_is_refused
    assert_raises(ArgumentError) { ISIS::SubTlv::SidLabel.new(label: 0x100000) }
    assert_raises(ArgumentError) { ISIS::SubTlv::SidLabel.new(label: 1, index: 1) }
  end

  # RFC 8667 section 3.1's example: three descriptors, in the order sent,
  # "SR-Cap: range: 100, SID value: 100", then 1000, then 500. 1 + 3 * 8 is
  # 25, 19.
  def test_several_descriptors_keep_their_order
    s = ISIS::SubTlv::SrCapabilities.new(flags: %w[I], descriptors: [{ range: 100, label: 100 },
                                                                     { range: 100, label: 1000 },
                                                                     { range: 100, label: 500 }])
    assert_equal "021980" "000064" "0103000064" "000064" "01030003e8" "000064" "01030001f4", s.to_shex
    assert_equal [[100, 199], [1000, 1099], [500, 599]], ISIS::SubTlv::SrCapabilities.new(octets(s.to_shex)).ranges
  end

  # A descriptor whose sub-TLV is a 4-octet index, not a label, keeps it.
  def test_a_descriptor_with_an_index
    s = ISIS::SubTlv::SrCapabilities.new(octets("020a80" "000064" "010400000007"))
    assert_equal({ flags: ["I"], descriptors: [{ range: 100, sid_label: { sid_label: { index: 7 } } }] }, s.to_hash)
    assert_equal "020a80000064010400000007", ISIS::SubTlv::SrCapabilities.new(s.to_hash).to_shex
    assert_empty s.ranges
  end

  # SR-Algorithm, section 3.2: one octet per algorithm, 0 SPF, 1 strict SPF.
  def test_sr_algorithm
    s = ISIS::SubTlv::SrAlgorithm.new(0, 1)
    assert_equal "13020001", s.to_shex
    assert_equal [0, 1], ISIS::SubTlv::SrAlgorithm.new(octets("13020001")).to_hash
    assert_raises(ArgumentError) { ISIS::SubTlv::SrAlgorithm.new(256) }
  end
end
