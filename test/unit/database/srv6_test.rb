# frozen_string_literal: true

require_relative "../../test_helper"

# ISIS::Srv6::Local, this system's SRv6 (docs/design/srv6.md, step 2):
# the srv6 block checked, the SIDs allocated from the locator, and a
# locator propagated between levels.
class TestSrv6Local < Minitest::Test
  STRUCTURE = { block: 32, node: 16, function: 16, argument: 0 }.freeze

  def config(locators: [{ name: "main", prefix: "fc00:0:1::/48", structure: STRUCTURE }], **more)
    { locators: locators }.merge(more)
  end

  def local(srv6 = config, ipv6: true, router_id: "10.255.0.1", ipv6_prefixes: [], no_end_x: [])
    ISIS::Srv6::Local.from_config(srv6, ipv6: ipv6, router_id: router_id, prefixes: [], ipv6_prefixes: ipv6_prefixes,
                                        no_end_x: no_end_x)
  end

  def refused(pattern, srv6 = config, **opts)
    e = assert_raises(ArgumentError) { local(srv6, **opts) }
    assert_match pattern, e.message
  end

  def test_absent_is_off
    assert_nil local(nil)
  end

  # End is function 0, End.DT6 1, End.X from 2, each with the locator
  # in front: fc00:0:1:: , fc00:0:1:1:: , fc00:0:1:2:: .
  def test_functions
    s = local
    assert_equal ["sr0", true], [s.interface, s.decap]
    x = s.end_x_sids("eth1", "\x00\x00\x00\x00\x00\x02".b)
    assert_equal "fc00:0:1:2::", x.first[:end_x_sid][:sid]
    assert_equal "fc00:0:1:2::", s.end_x_sids("eth1", "\x00\x00\x00\x00\x00\x02".b).first[:end_x_sid][:sid], "the same"
    assert_equal "fc00:0:1:3::", s.end_x_sids("eth2", "\x00\x00\x00\x00\x00\x03".b).first[:end_x_sid][:sid]
    assert_equal [%w[fc00:0:1:: End], %w[fc00:0:1:1:: End.DT6], %w[fc00:0:1:2:: End.X], %w[fc00:0:1:3:: End.X]],
                 s.sids.map { _1.values_at(:sid, :behavior) }
  end

  # TLV 27's entry: metric 0, algorithm 0, Prefix Attribute Flags with
  # none set, the End SID and the End.DT6 SID, each with its structure.
  def test_locator_entry
    e = local.locator_entries.first
    assert_equal({ locator: "fc00:0:1::/48", metric: 0, algorithm: 0,
                   subtlvs: [{ prefix_attribute_flags: {} },
                             { end_sid: { behavior: "End", sid: "fc00:0:1::", subtlvs: [{ sid_structure: STRUCTURE }] } },
                             { end_sid: { behavior: "End.DT6", sid: "fc00:0:1:1::", subtlvs: [{ sid_structure: STRUCTURE }] } }] },
                 e.to_hash)
    assert_equal 1, local(config(decap: false)).locator_entries.first.subtlvs_of(ISIS::SubTlv::Srv6EndSid).size
    assert_equal [{ prefix: "fc00:0:1::/48", metric: 0, subtlvs: [{ prefix_attribute_flags: {} }] }], local.locator_prefixes
  end

  # Structure 40/24/8/0 on a /64: the function is the eight bits after
  # the locator.
  def test_another_structure
    s = local(config(locators: [{ prefix: "2001:db8:0:1::/64", structure: { block: 40, node: 24, function: 8 } }]))
    assert_equal "2001:db8:0:1:200::", s.end_x_sids("e", "x").first[:end_x_sid][:sid]
    assert_equal "locator0", s.locators.first.name
  end

  def test_lan_end_x_and_no_end_x
    s = local(no_end_x: ["eth9"])
    lan = s.lan_end_x_sids("eth1", ["\x00\x00\x00\x00\x00\x02".b, "\x00\x00\x00\x00\x00\x03".b])
    assert_equal [["0000.0000.0002", "fc00:0:1:2::"], ["0000.0000.0003", "fc00:0:1:3::"]],
                 lan.map { _1[:lan_end_x_sid].values_at(:neighbor, :sid) }
    assert_empty s.end_x_sids("eth9", "x")
  end

  def test_refusals
    refused(/srv6 needs ipv6: true/, ipv6: false)
    refused(/srv6: unknown key locator; the keys are locators, interface, decap, receive_policy/, { locator: [] })
    refused(/srv6 needs at least one locator/, { locators: [] })
    refused(/needs a router_id/, router_id: nil)
    refused(/10.0.0.0\/8 is not an IPv6 prefix/, config(locators: [{ prefix: "10.0.0.0/8", structure: STRUCTURE }]))
    refused(/a structure is needed/, config(locators: [{ prefix: "fc00:0:1::/48" }]))
    refused(/block 32 and node 8 are 40 bits, the locator \/48/,
            config(locators: [{ prefix: "fc00:0:1::/48", structure: STRUCTURE.merge(node: 8) }]))
    refused(/the structure is 144 bits, past 128/,
            config(locators: [{ prefix: "fc00:0:1::/48", structure: STRUCTURE.merge(function: 64, argument: 32) }]))
    refused(/algorithm 0 only/, config(locators: [{ prefix: "fc00:0:1::/48", algorithm: 128, structure: STRUCTURE }]))
    refused(/overlap/, config(locators: [{ name: "a", prefix: "fc00:0:1::/48", structure: STRUCTURE },
                                         { name: "b", prefix: "fc00:0:1:8000::/64",
                                           structure: { block: 48, node: 16, function: 16 } }]))
    refused(/locator main is also in ipv6_prefixes/, ipv6_prefixes: [{ prefix: "fc00:0:1::/48", metric: 0 }])
    refused(/bits set past \/48/, config(locators: [{ prefix: "fc00:0:1:1::/48", structure: STRUCTURE }]))
    refused(/unknown key nodes/, config(locators: [{ prefix: "fc00:0:1::/48", structure: STRUCTURE.merge(nodes: 1) }]))
    refused(/decap is true or false/, config(decap: "yes"))
  end

  # Down from Level 2: D set, R added to the Prefix Attribute Flags, the
  # others kept, the SIDs kept. Up from Level 1: D as it came, R. With no
  # Prefix Attribute Flags, one is added: section 7.1's MUST.
  def test_propagated
    e = local.locator_entries.first.to_hash
    e[:subtlvs][0] = { prefix_attribute_flags: { flags: %w[A] } }
    down = ISIS::Srv6::Local.propagated(e, down: true, metric: 20)
    assert_equal [20, %w[D]], [down.metric, down.flag_letters]
    assert_equal %w[R A], down.subtlvs_of(ISIS::SubTlv::PrefixAttributeFlags).first.flag_letters
    assert_equal 2, down.subtlvs_of(ISIS::SubTlv::Srv6EndSid).size
    bare = ISIS::Tlv::Srv6Locator::Entry.new(locator: "fc00:0:9::/48", metric: 5)
    up = ISIS::Srv6::Local.propagated(bare, down: false)
    assert_equal [5, []], [up.metric, up.flag_letters]
    assert_equal [ISIS::SubTlv::PrefixAttributeFlags], up.subtlvs.map(&:class)
    assert_equal %w[R], up.subtlvs.first.flag_letters
  end
end
