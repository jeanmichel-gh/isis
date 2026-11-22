# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "json"
require "rbconfig"

# A TI-LFA backup route in the Linux kernel, through isisd's own netlink
# adapter and Host#ti_lfa, in network namespaces: the route to
# 192.0.2.2/32 at priority 21 on the link to b, its backup at 121 on the
# link to c pushing two labels. b's end of the link goes down, so the
# link loses carrier, and the kernel must take the backup by itself, with
# no daemon running (docs/ti-lfa.md; routescope docs/design/ti-lfa.md,
# "The data plane").
#
#   sudo env "PATH=$PATH" ISIS_FRR=1 rake interop
#
# Root, iproute2 and the mpls_iptunnel module. Skips without them, unless
# ISIS_FRR=1, as the interop tier runs in CI: then it fails.
class TestKernelBackup < Minitest::Test
  def setup
    why = missing
    if why
      flunk(why) if ENV["ISIS_FRR"] == "1"
      skip(why)
    end
    @ns = { a: "ikb#{Process.pid}a", b: "ikb#{Process.pid}b", c: "ikb#{Process.pid}c" }
    @ns.each_value { |n| sh("ip netns add #{n}") }
    sh("ip link add pri netns #{@ns[:a]} type veth peer name pri netns #{@ns[:b]}")
    sh("ip link add bak netns #{@ns[:a]} type veth peer name bak netns #{@ns[:c]}")
    { a: [["pri", "10.1.0.1"], ["bak", "10.2.0.1"]], b: [["pri", "10.1.0.2"]], c: [["bak", "10.2.0.2"]] }.each do |k, ifs|
      sh("ip -n #{@ns[k]} link set lo up")
      ifs.each do |name, addr|
        sh("ip -n #{@ns[k]} addr add #{addr}/24 dev #{name}")
        sh("ip -n #{@ns[k]} link set #{name} up")
      end
    end
  end

  def teardown
    @ns&.each_value { |n| system("ip netns del #{n} 2>/dev/null") }
  end

  def missing
    return "needs root" unless Process.uid.zero?
    return "needs iproute2" unless system("which ip > /dev/null")
    unless File.read("/proc/modules").include?("mpls_iptunnel")
      return "needs the mpls_iptunnel module, to push labels: sudo modprobe mpls_iptunnel"
    end

    nil
  rescue Errno::ENOENT
    "needs /proc/modules"
  end

  def sh(cmd)
    out, err, status = Open3.capture3(cmd)
    raise "#{cmd}: #{err}" unless status.success?

    out
  end

  # Ruby in a's namespace, with isisd's library: +code+ has +nl+, the
  # adapter at priority 21, +a+ and +c+, the adjacencies to b and c.
  def in_a(code)
    script = <<~RUBY
      require "isis4r"
      log = ISIS::Runtime::Log.new(clock: ISIS::Runtime::MonotonicClock.new)
      nl = ISIS::Forwarding::Netlink.new(log: log, priority: 21)
      b = ISIS::Spf::Adjacency.new(circuit: "pri", neighbor: "\\x00\\x00\\x00\\x00\\x00\\x02".b, circuit_id: 1, address: "10.1.0.2")
      c = ISIS::Spf::Adjacency.new(circuit: "bak", neighbor: "\\x00\\x00\\x00\\x00\\x00\\x03".b, circuit_id: 1, address: "10.2.0.2")
      #{code}
    RUBY
    env = { "RUBYLIB" => $LOAD_PATH.join(":") }
    out, err, status = Open3.capture3(env, "ip", "netns", "exec", @ns[:a], RbConfig.ruby, "-e", script)
    raise "#{err}#{out}" unless status.success?

    out
  end

  def routes = JSON.parse(sh("ip -n #{@ns[:a]} -j route show 192.0.2.2/32"))

  def via = sh("ip -n #{@ns[:a]} route get 192.0.2.2").lines.first

  # The kernel marks a route on a link that lost carrier after its link
  # watch runs: 8 to 75 ms on ospflab, five runs (docs/ti-lfa.md). Wait up
  # to a second for it.
  def until_via(pattern)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
    line = via
    until line.match?(pattern) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
      line = via
    end
    line
  end

  def test_the_kernel_takes_the_backup_on_carrier_loss
    in_a(<<~RUBY)
      raise "sysctls" if ISIS::Router::Host.new(log: log).ti_lfa(%w[pri bak])
      route = ISIS::Spf::Route.new("192.0.2.2/32", 10, [b])
      raise "route" unless nl.apply(ISIS::Forwarding::Operation.new(kind: :install, route: route, labels: { ["pri", b.neighbor] => 18_002 }))
      backup = ISIS::Forwarding::BackupOperation.new(kind: :install, prefix: "192.0.2.2/32", family: :ipv4, adjacency: c, labels: [20_004, 22_002])
      raise "backup" unless nl.apply(backup)
    RUBY
    assert_equal [21, 121], routes.map { _1["metric"] }.sort
    assert_equal ["bak", "10.2.0.2"], routes.find { _1["metric"] == 121 }.values_at("dev", "gateway")
    assert_match(%r{encap mpls\s+20004/22002 via 10.2.0.2 dev bak}, sh("ip -n #{@ns[:a]} route show 192.0.2.2/32 metric 121"))
    assert_match(/encap mpls\s+18002 via 10.1.0.2 dev pri/, via)

    sh("ip -n #{@ns[:b]} link set pri down")
    took = %r{encap mpls\s+20004/22002 via 10.2.0.2 dev bak}
    assert_match(took, until_via(took), "the kernel took the backup")

    sh("ip -n #{@ns[:b]} link set pri up")
    assert_match(/dev pri/, until_via(/dev pri/), "and the route again when carrier is back")
  end

  # Withdrawn, the backup goes and the route stays; a flush takes both.
  def test_withdrawn_then_flushed
    in_a(<<~RUBY)
      nl.apply(ISIS::Forwarding::Operation.new(kind: :install, route: ISIS::Spf::Route.new("192.0.2.2/32", 10, [b])))
      nl.apply(ISIS::Forwarding::BackupOperation.new(kind: :install, prefix: "192.0.2.2/32", family: :ipv4, adjacency: c, labels: [20_004]))
      nl.apply(ISIS::Forwarding::BackupOperation.new(kind: :withdraw, prefix: "192.0.2.2/32", family: :ipv4))
    RUBY
    assert_equal [21], routes.map { _1["metric"] }
    in_a(<<~RUBY)
      nl.apply(ISIS::Forwarding::BackupOperation.new(kind: :install, prefix: "192.0.2.2/32", family: :ipv4, adjacency: c, labels: [20_004]))
      nl.flush
    RUBY
    assert_empty routes
  end
end
