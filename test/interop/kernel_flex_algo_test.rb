# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/frr_lab"
require "json"
require "socket"
require "yaml"
require "tmpdir"
require "fileutils"
require "rbconfig"

# A flex-algo's label routes in the Linux kernel (docs/design/
# flex-algo.md, step 5): exe/isisd in three network namespaces in a line,
# S - A - D, all taking part in algorithm 128, D advertising its FAD. S
# installs its label routes. D's loopback has Prefix-SID index 3 for
# algorithm 0 and 103 for 128, and each system N has the SRGB
# 16000 + 1000 N, so S takes 17003 and 17103 and swaps them to A's 18003
# and 18103.
#
# Then D's FAD includes only red, a color no link has: every link is
# pruned from 128 (RFC 9350 section 13, rule 3), so S withdraws 17103
# (section 14.1), and keeps 17003.
#
#   sudo env "PATH=$PATH" ISIS_FRR=1 rake interop
#
# Root, iproute2 and the mpls_router module. Skips without them, unless
# ISIS_FRR=1, as the interop tier runs in CI: then it fails.
class TestKernelFlexAlgo < Minitest::Test
  SYSTEMS = %w[S A D].freeze
  LINKS = [%w[S A], %w[A D]].freeze

  def setup
    why = missing
    if why
      flunk(why) if ENV["ISIS_FRR"] == "1"
      skip(why)
    end
    @prefix = "ikf#{Process.pid}"
    @dir = Dir.mktmpdir("isis4r-kernel-flex")
    @pids = {}
    SYSTEMS.each do |s|
      sh "ip netns add #{ns(s)}"
      sh "ip -n #{ns(s)} link set lo up"
      sh "ip -n #{ns(s)} addr add 10.255.0.#{number(s)}/32 dev lo"
    end
    LINKS.each_with_index do |(a, b), k|
      sh "ip link add to#{b} netns #{ns(a)} type veth peer name to#{a} netns #{ns(b)}"
      sh "ip -n #{ns(a)} addr add 10.1.#{k}.1/24 dev to#{b}"
      sh "ip -n #{ns(b)} addr add 10.1.#{k}.2/24 dev to#{a}"
      sh "ip -n #{ns(a)} link set to#{b} up"
      sh "ip -n #{ns(b)} link set to#{a} up"
    end
    sh "ip netns exec #{ns('S')} sysctl -qw net.mpls.platform_labels=100000"
    SYSTEMS.each { start(_1) }
  end

  def teardown
    @pids&.each_value do |pid|
      Process.kill("TERM", pid)
      Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
    SYSTEMS.each { system("ip netns del #{ns(_1)} 2>/dev/null") } if @prefix
    FileUtils.rm_rf(@dir) if @dir
  end

  def missing
    return "needs root" unless Process.uid.zero?
    return "needs iproute2" unless system("which ip > /dev/null")
    return "needs the mpls_router module: sudo modprobe mpls_router" unless File.read("/proc/modules").include?("mpls_router")

    nil
  rescue Errno::ENOENT
    "needs /proc/modules"
  end

  def number(name) = SYSTEMS.index(name) + 1
  def ns(name) = "#{@prefix}-#{name}"
  def socket(name) = File.join(@dir, "#{name}.sock")
  def srgb(name) = 16_000 + (1_000 * number(name))

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}"
  end

  def start(name)
    interfaces = LINKS.each_with_index.filter_map do |(a, b), k|
      if a == name then ["to#{b}", "10.1.#{k}.1"]
      elsif b == name then ["to#{a}", "10.1.#{k}.2"]
      end
    end
    config = {
      "system_id" => format("0000.0000.%04d", number(name)), "hostname" => name, "areas" => ["49.0001"],
      "level" => 1, "metric_style" => "wide", "minimum_lsp_interval" => 1, "forwarding" => name == "S",
      "segment_routing" => { "srgb" => [{ "start" => srgb(name), "size" => 1_000 }] },
      "affinity_map" => { "red" => 1 },
      "flex_algo" => [{ "algorithm" => 128, "advertise" => name == "D", "priority" => 100 }],
      "prefixes" => [{ "prefix" => "10.255.0.#{number(name)}/32", "metric" => 0, "sid" => number(name),
                       "algorithm_sids" => { 128 => 100 + number(name) } }],
      "interfaces" => interfaces.map do |iface, address|
        { "name" => iface, "ip_addresses" => [address], "metric" => 10, "hello_interval" => 1, "hello_multiplier" => 3 }
      end
    }
    file = File.join(@dir, "#{name}.yml")
    File.write(file, config.to_yaml)
    @pids[name] = Process.spawn("ip", "netns", "exec", ns(name), RbConfig.ruby, "#{FrrLab::ROOT}/exe/isisd", "-c", file,
                                "-s", socket(name), "-l", "-", %i[out err] => File.join(@dir, "#{name}.log"))
  end

  def isisd(name, method, params = {})
    s = UNIXSocket.new(socket(name))
    s.write(JSON.generate(id: 1, method: method, params: params) + "\n")
    r = JSON.parse(s.gets)
    raise r["error"] if r["error"]

    r["result"]
  ensure
    s&.close
  end

  # S's label routes in the kernel: in-label => out-labels, as
  # iproute2 gives them ("to": "18003", or "18003/18004" for a stack).
  def kernel_labels
    JSON.parse(`ip -n #{ns('S')} -j -M route show`).to_h do |r|
      [Integer(r["dst"]), r["to"].to_s.split("/").map { Integer(_1) }]
    end
  end

  def wait_for(timeout = 60)
    deadline = Time.now + timeout
    until Time.now > deadline
      return true if yield

      sleep 0.5
    end
    false
  end

  def logs = SYSTEMS.map { "#{_1}: #{File.read(File.join(@dir, "#{_1}.log")).lines.last(15).join}" }.join("\n")

  def test_installed_then_removed
    d0 = srgb("S") + 3
    d128 = srgb("S") + 103
    assert wait_for { kernel_labels.key?(d128) && kernel_labels.key?(d0) }, "no label routes in S: #{kernel_labels}\n#{logs}"
    assert_equal [srgb("A") + 3], kernel_labels[d0]
    assert_equal [srgb("A") + 103], kernel_labels[d128]
    row = isisd("S", "show.labels").find { _1["label"] == d128 }
    assert_equal 128, row["algorithm"]

    isisd("D", "policy.flex_algo", { "algorithm" => 128, "include_any" => ["red"] })
    assert wait_for { !kernel_labels.key?(d128) }, "17103 still in S: #{kernel_labels}\n#{logs}"
    assert_equal [srgb("A") + 3], kernel_labels[d0], "algorithm 0's label stays"
  end
end
