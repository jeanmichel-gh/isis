# frozen_string_literal: true

require_relative "../../test_helper"
require "tmpdir"

# The Linux host's reads that need no root: an interface's MAC from sysfs
# and its link-local addresses from /proc/net/if_inet6, here from files
# laid out as the kernel lays them out.
class TestRouterHost < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    FileUtils.mkdir_p(File.join(@dir, "net", "eth1"))
    File.write(File.join(@dir, "net", "eth1", "address"), "02:00:00:00:00:01\n")
    # address, index, prefix length, scope, flags, name; scope 20 is link.
    File.write(File.join(@dir, "if_inet6"), <<~INET6)
      fe800000000000000000000000000001 03 40 20 80     eth1
      20010db8000000000000000000000001 03 40 00 80     eth1
      fe800000000000000000000000000002 04 40 20 80     eth2
    INET6
    @host = ISIS::Router::Host.new(log: nil, sysfs: File.join(@dir, "net"), if_inet6: File.join(@dir, "if_inet6"))
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def test_mac
    assert_equal "02:00:00:00:00:01", @host.mac("eth1")
  end

  def test_link_local_is_scope_20_on_that_interface
    assert_equal ["fe80::1"], @host.link_local("eth1")
  end

  def test_no_if_inet6_means_no_ipv6
    host = ISIS::Router::Host.new(log: nil, if_inet6: File.join(@dir, "none"))
    assert_equal [], host.link_local("eth1")
  end

  def test_forwarding_priority_by_level
    assert_equal [21, 22], [1, 2].map { |l| @host.forwarding(l).priority }
  end
end
