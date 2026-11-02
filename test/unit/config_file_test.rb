# frozen_string_literal: true

require_relative "../test_helper"

# YAML reads 49.0010 as the number 49.001. ConfigFile takes every list
# under an "areas" key, at any depth, as the file wrote it.
class TestConfigFile < Minitest::Test
  def test_areas_as_written_at_any_depth
    h = ISIS::ConfigFile.parse(<<~YAML)
      areas: [49.0010, '49.0002']
      simulator:
        areas: [49.0100]
      routers:
        - { name: x, areas: [49.0010] }
        - { name: y, areas: 49.0003 }
      metric: 10
    YAML
    assert_equal %w[49.0010 49.0002], h["areas"]
    assert_equal ["49.0100"], h.dig("simulator", "areas")
    assert_equal [["49.0010"], ["49.0003"]], h["routers"].map { _1["areas"] }
    assert_equal 10, h["metric"]
  end

  def test_other_numbers_stay_numbers
    assert_equal({ "hello_interval" => 0.5, "level" => "1-2" }, ISIS::ConfigFile.parse("hello_interval: 0.5\nlevel: 1-2\n"))
  end

  def test_refusals_name_the_source
    e = assert_raises(ArgumentError) { ISIS::ConfigFile.parse("- a\n", source: "x.yml") }
    assert_equal "x.yml: the configuration is a mapping", e.message
    e = assert_raises(ArgumentError) { ISIS::ConfigFile.parse("a: [\n", source: "x.yml") }
    assert_match(/\Ax.yml: /, e.message)
    assert_raises(ArgumentError) { ISIS::ConfigFile.parse("areas: [{ a: 1 }]\n") }
  end
end
