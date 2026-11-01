# frozen_string_literal: true

require_relative "../../test_helper"

# Every cell of the RFC 5303 section 3.2 table, written out from the
# section rather than from the code's TABLE, so a transposed table fails.
class TestThreeWay < Minitest::Test
  CELLS = [
    [:down, :down, :initialize], [:down, :initializing, :up], [:down, :up, :down],
    [:initializing, :down, :initialize], [:initializing, :initializing, :up], [:initializing, :up, :up],
    [:up, :down, :initialize], [:up, :initializing, :accept], [:up, :up, :accept]
  ].freeze

  def test_every_cell
    CELLS.each do |current, received, action|
      assert_equal action, ISIS::Adjacency::ThreeWay.action(current, received), "#{current} receiving #{received}"
    end
  end

  def test_states_after_each_action
    assert_equal :initializing, ISIS::Adjacency::ThreeWay.after(:initialize, :down)
    assert_equal :up, ISIS::Adjacency::ThreeWay.after(:up, :initializing)
    assert_equal :up, ISIS::Adjacency::ThreeWay.after(:accept, :up)
    assert_nil ISIS::Adjacency::ThreeWay.after(:down, :down)
  end

  def test_unknown_states_are_refused
    assert_raises(ArgumentError) { ISIS::Adjacency::ThreeWay.action(:sideways, :up) }
    assert_raises(ArgumentError) { ISIS::Adjacency::ThreeWay.action(:up, 7) }
  end
end
