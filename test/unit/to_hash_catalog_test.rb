# frozen_string_literal: true

require_relative "../test_helper"
require_relative "to_hash_catalog"

# Measures test/unit/to_hash_catalog.rb against the library: each declared
# round trip holds, and every class that includes ISIS::Node is in exactly
# one of its three lists.
class TestToHashCatalog < Minitest::Test
  C = ToHashCatalog

  # As test/docs/building_objects_test.rb finds them.
  INCLUDE = Module.instance_method(:include?)

  def node_classes
    ObjectSpace.each_object(Class)
               .select { |c| INCLUDE.bind_call(c, ISIS::Node) && c.name&.start_with?("ISIS::") }
               .map(&:name).sort
  end

  def test_each_declared_round_trip_holds
    C::ROUND_TRIPS.each do |name, recipes|
      klass = Object.const_get(name)
      recipes.each do |hex|
        parsed = klass.new(ISIS::Octets.from_hex(hex))
        assert_equal hex, parsed.to_shex, "#{name} #{hex}: the octets"
        hash = parsed.to_hash
        again = klass.new(hash)
        assert_equal hex, again.to_shex, "#{name} #{hex}: rebuilt from its hash"
        assert_equal hash, again.to_hash, "#{name} #{hex}: the hash again"
      end
    end
  end

  # A declared gap is still a gap; when it closes, it moves to ROUND_TRIPS.
  def test_each_declared_gap_still_loses
    C::GAPS.each do |name, gap|
      klass = Object.const_get(name)
      parsed = klass.new(ISIS::Octets.from_hex(gap.fetch(:recipe)))
      refute_equal parsed.to_shex, klass.new(parsed.to_hash).to_shex, "#{name} round trips now: move it"
    end
  end

  def test_every_node_class_is_in_exactly_one_list
    lists = [C::ROUND_TRIPS.keys, C::GAPS.keys, C::UNMEASURED]
    all = lists.flatten
    refute_empty node_classes, "discovery found nothing, so it is broken"
    assert_equal all.uniq.size, all.size, "a class is in two lists"
    assert_equal node_classes, all.sort
  end
end
