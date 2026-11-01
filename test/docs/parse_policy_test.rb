# frozen_string_literal: true

require_relative "../test_helper"
Dir[File.expand_path("../unit/**/*_test.rb", __dir__)].sort.each { |f| require f }

# docs/parse-policy.md names the tests that hold each rule. Every rule must
# name at least one, and every test it names must exist, so the doc cannot
# point at a test that was renamed or deleted.
class TestParsePolicyDoc < Minitest::Test
  DOC = File.read(File.expand_path("../../docs/parse-policy.md", __dir__))

  def rules
    DOC.split(/^## /).drop(1).select { |s| s =~ /\A\d\. / }
  end

  def named_tests(text)
    text.scan(/`(Test\w+)#(test_\w+)`/)
  end

  def test_there_are_seven_rules
    assert_equal 7, rules.size
  end

  def test_every_rule_names_a_test
    rules.each do |rule|
      refute_empty named_tests(rule), "rule #{rule[0, 40].inspect} names no test"
    end
  end

  def test_every_named_test_exists
    named = named_tests(DOC)
    refute_empty named
    named.each do |klass, method|
      assert Object.const_defined?(klass), "#{klass} does not exist"
      assert_includes Object.const_get(klass).public_instance_methods, method.to_sym, "#{klass}##{method} does not exist"
    end
  end
end
