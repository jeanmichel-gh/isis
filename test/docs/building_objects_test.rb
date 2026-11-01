# frozen_string_literal: true

require_relative "../test_helper"

# docs/building-objects.md makes two claims the code has to keep true: the
# dispatch order of ISIS::Node#initialize, and the list of classes that
# follow it. Both are checked against the library, not against a copy.
class TestBuildingObjectsDoc < Minitest::Test
  DOC = File.read(File.expand_path("../../docs/building-objects.md", __dir__))

  # A node that records which way it was built.
  class Probe
    include ISIS::Node
    attr_reader :way

    def encode
      "x".b
    end

    private

    def parse(_octets)
      @way = :octets
    end

    def from_hash(_hash)
      @way = :hash
    end

    def from_fields(*_args, **_fields)
      @way = :fields
    end
  end

  def test_octets_are_parsed
    assert_equal :octets, Probe.new(ISIS::Octets.new("x")).way
  end

  def test_an_instance_is_copied_through_its_encoding
    assert_equal :octets, Probe.new(Probe.new(1)).way
  end

  def test_a_hash_is_rebuilt
    assert_equal :hash, Probe.new({ a: 1 }).way
  end

  def test_everything_else_is_fields
    assert_equal :fields, Probe.new("x".b).way, "a plain String is a field value"
    assert_equal :fields, Probe.new(1, 2).way
    assert_equal :fields, Probe.new(a: 1).way, "keywords are fields, not a hash"
    assert_equal :fields, Probe.new.way
  end

  def documented_classes
    DOC.scan(/^- `(ISIS::[\w:]+)`$/).flatten.sort
  end

  # Module#include? is bound directly because every class in the process is
  # asked, and some redefine include? as a class method: RubyGems' Molinillo
  # Log does, and calling its version raises.
  INCLUDE = Module.instance_method(:include?)

  def node_classes
    ObjectSpace.each_object(Class)
               .select { |c| INCLUDE.bind_call(c, ISIS::Node) && c.name&.start_with?("ISIS::") }
               .map(&:name).sort
  end

  def test_every_node_class_is_documented_and_every_documented_class_exists
    refute_empty node_classes, "discovery found nothing, so it is broken"
    assert_equal node_classes, documented_classes
  end
end
