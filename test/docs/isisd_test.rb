# frozen_string_literal: true

require_relative "../test_helper"

# docs/isisd.md lists every API method, and nothing the API lacks: the
# list is read from the API, so a new method fails here until the guide
# has it.
class TestDocsIsisd < Minitest::Test
  DOC = File.read(File.expand_path("../../docs/isisd.md", __dir__))

  def documented
    DOC[/^Every method:\n(.*?)\n\n/m, 1].scan(/^\| `([a-z.]+)` \|/).flatten
  end

  def test_every_method_is_documented
    methods = ISIS::Daemon::Api::METHODS.keys + ISIS::Daemon::Api::STREAM_METHODS
    assert_empty methods - documented, "docs/isisd.md does not list these methods"
  end

  def test_every_documented_method_exists
    methods = ISIS::Daemon::Api::METHODS.keys + ISIS::Daemon::Api::STREAM_METHODS
    refute_empty documented
    assert_empty documented - methods, "docs/isisd.md lists methods the API does not have"
  end

  def test_the_documented_socket_is_the_default
    assert_includes DOC, "`#{ISIS::Daemon::SOCKET}`"
  end
end
