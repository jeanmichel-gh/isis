# frozen_string_literal: true

require "json"
require "socket"
require "yaml"
require "fileutils"
require "tmpdir"
require "open3"
require "rbconfig"
require_relative "frr_lab"

# The fault catalog's SR entries (ISIS::Fault::CATALOG) to two receivers
# at once: an isis4r-sim, s1, with one simulated system, r, behind it,
# faces exe/isisd on one link and FRR's isisd on the other. A fault is
# put in r's LSPs through the simulator's HTTP API (POST /api/fault), so
# both receivers learn the same LSP. Needs what FrrLab needs; the tests
# that use it run only with ISIS_FRR=1.
#
#            toI 10.2.1.0/24      toF 10.2.2.0/24
#   isisd ------------------ s1 ------------------ FRR
#   0000.0000.0001           |  0000.0000.0009     0000.0000.0002
#   SRGB 16000               r  0000.0000.0005     SRGB 18000
#                               SRGB 20000, 10.255.0.5/32 index 5
#
# Each SRGB is 8000 labels, so a fault's index near the top of r's block
# (Simulator#fault) fits every receiver's.
class SrFaultLab
  FRR = FrrLab::FRR
  ROOT = FrrLab::ROOT
  HTTP_PORT = 8080
  ISISD_SRGB = 16_000
  FRR_SRGB = 18_000
  R_SRGB = ISIS::Fault::SRGB.first
  SIZE = 8_000

  attr_reader :dir

  # With +flex+, isisd and FRR take part in algorithm 128 without a FAD
  # of their own, so a FAD in s1's LSP is the only one; FRR runs mpls-te
  # so it reads link attributes. For the flex-algo entries
  # (ISIS::Fault::FLEX_ALGO_CATALOG).
  def initialize(prefix, flex: false)
    @flex = flex
    @prefix = prefix
    @dir = Dir.mktmpdir("isis4r-#{prefix}")
    @run = "/var/run/frr/#{prefix}"
    @etc = "/etc/frr/#{prefix}"
    @pids = {}
  end

  def ns(name) = "#{@prefix}-#{name}"
  def socket(name) = File.join(@dir, "#{name}.sock")

  def start
    cleanup
    %w[sim isisd frr].each do |n|
      sh "ip netns add #{ns(n)}"
      sh "ip -n #{ns(n)} link set lo up"
    end
    [["isisd", "toI", 1], ["frr", "toF", 2]].each do |n, iface, k|
      sh "ip link add #{iface} netns #{ns('sim')} type veth peer name toS netns #{ns(n)}"
      sh "ip -n #{ns('sim')} addr add 10.2.#{k}.1/24 dev #{iface}"
      sh "ip -n #{ns(n)} addr add 10.2.#{k}.2/24 dev toS"
      sh "ip -n #{ns('sim')} link set #{iface} up"
      sh "ip -n #{ns(n)} link set toS up"
    end
    sh "ip -n #{ns('isisd')} addr add 10.255.0.1/32 dev lo"
    sh "ip -n #{ns('frr')} addr add 10.255.0.2/32 dev lo"
    # FRR's zebra installs its label routes in the kernel.
    sh "ip netns exec #{ns('frr')} sysctl -qw net.mpls.platform_labels=100000"
    start_sim
    start_isisd
    start_frr
    self
  end

  def stop
    cleanup
    FileUtils.rm_rf(@dir)
  end

  def wait_for(timeout = 60)
    deadline = Time.now + timeout
    until Time.now > deadline
      begin
        return true if yield
      rescue Errno::ENOENT, Errno::ECONNREFUSED, JSON::ParserError, RuntimeError
        nil
      end
      sleep 0.5
    end
    false
  end

  # One POST to the simulator's HTTP API, from inside its namespace.
  def sim(path, body = {})
    out, err, status = Open3.capture3("ip", "netns", "exec", ns("sim"), "curl", "-s", "-H", "X-ISIS4R: routescope",
                                      "-d", JSON.generate(body), "http://127.0.0.1:#{HTTP_PORT}#{path}")
    raise "#{path}: #{err}" unless status.success?

    JSON.parse(out)
  end

  # One isisd API call on the receiver.
  def isisd(method, params = {}) = api("isisd", method, params)

  # One API call on +who+'s socket: "isisd", or "sim", which answers
  # isisd's methods for the simulator's own system.
  def api(who, method, params = {})
    s = UNIXSocket.new(socket(who))
    s.write(JSON.generate(id: 1, method: method, params: params) + "\n")
    r = JSON.parse(s.gets)
    raise r["error"] if r["error"]

    r["result"]
  ensure
    s&.close
  end

  def vtysh(cmd)
    out, _err, status = Open3.capture3("ip", "netns", "exec", ns("frr"), "vtysh", "-N", @prefix, "-c", cmd)
    raise "vtysh #{cmd} failed" unless status.success?

    out
  end

  def frr_json(cmd) = JSON.parse(vtysh(cmd))

  def report
    Dir[File.join(@dir, "*.log")].map { |f| "--- #{File.basename(f)}\n#{File.read(f).lines.last(15).join}" }.join("\n")
  end

  private

  def start_sim
    iface = ->(name, k) { { "name" => name, "ip_addresses" => ["10.2.#{k}.1"], "hello_interval" => 1, "hello_multiplier" => 10 } }
    file = File.join(@dir, "sim.yml")
    File.write(file, {
      "simulator" => { "system_id" => "0000.0000.0009", "hostname" => "s1", "areas" => ["49.0001"], "level" => 1,
                       "metric_style" => "wide", "minimum_lsp_interval" => 1, "router_id" => "10.255.0.9",
                       "segment_routing" => { "srgb" => [{ "start" => 17_000, "size" => SIZE }] },
                       "interfaces" => [iface.call("toI", 1), iface.call("toF", 2)] },
      "segment_routing" => {},
      "routers" => [{ "name" => "r", "system_id" => "0000.0000.0005", "loopback" => "10.255.0.5", "sid" => 5,
                      "srgb" => [{ "start" => R_SRGB, "size" => SIZE }] }],
      "links" => [{ "from" => "s1", "to" => "r" }]
    }.to_yaml)
    @pids["sim"] = Process.spawn("ip", "netns", "exec", ns("sim"), RbConfig.ruby, "#{ROOT}/exe/isis4r-sim", "-c", file,
                                 "-s", socket("sim"), "--http", "127.0.0.1:#{HTTP_PORT}", "-l", "-",
                                 %i[out err] => File.join(@dir, "sim.log"))
  end

  def start_isisd
    file = File.join(@dir, "isisd.yml")
    File.write(file, {
      "system_id" => "0000.0000.0001", "hostname" => "isisd", "areas" => ["49.0001"], "level" => 1,
      "metric_style" => "wide", "minimum_lsp_interval" => 1,
      "segment_routing" => { "srgb" => [{ "start" => ISISD_SRGB, "size" => SIZE }] },
      "prefixes" => [{ "prefix" => "10.255.0.1/32", "metric" => 0, "sid" => 1 }],
      "interfaces" => [{ "name" => "toS", "ip_addresses" => ["10.2.1.2"], "hello_interval" => 1, "hello_multiplier" => 10 }]
    }.merge(@flex ? { "flex_algo" => [{ "algorithm" => 128, "advertise" => false }] } : {}).to_yaml)
    @pids["isisd"] = Process.spawn("ip", "netns", "exec", ns("isisd"), RbConfig.ruby, "#{ROOT}/exe/isisd", "-c", file,
                                   "-s", socket("isisd"), "-l", "-", %i[out err] => File.join(@dir, "isisd.log"))
  end

  def start_frr
    FileUtils.mkdir_p([@run, @etc])
    conf = File.join(@etc, "frr.conf")
    # lsp-gen-interval comes first: is-type schedules an LSP, at the
    # interval then set. After it, FRR 10.5.1 kept its 30 s default, and its
    # own LSP stayed empty for 30 s (2026-11-27).
    File.write(conf, <<~CONF)
      hostname frr
      log file #{File.join(@dir, 'frr.log')} informational
      interface toS
       ip router isis LAB
       isis network point-to-point
       isis hello-interval 1
       isis hello-multiplier 10
      interface lo
       ip router isis LAB
       isis passive
      router isis LAB
       lsp-gen-interval 1
       net 49.0001.0000.0000.0002.00
       is-type level-1
       metric-style wide
       segment-routing on
       segment-routing global-block #{FRR_SRGB} #{FRR_SRGB + SIZE - 1}
       segment-routing prefix 10.255.0.2/32 index 2
      #{@flex ? " mpls-te on\n mpls-te router-address 10.255.0.2\n flex-algo 128\n  dataplane sr-mpls\n exit" : ''}
    CONF
    zebra = File.join(@etc, "zebra.conf")
    File.write(zebra, "hostname frr\n")
    FileUtils.touch(File.join(@dir, "frr.log"))
    sh "chown -R frr:frr #{@run} #{@etc} #{@dir}"
    { "zebra" => zebra, "isisd" => conf }.each do |d, f|
      out = File.join(@dir, "#{d}.start.log")
      cmd = "ip netns exec #{ns('frr')} #{FRR}/#{d} -N #{@prefix} -d -f #{f} -i #{@run}/#{d}.pid"
      system("#{cmd} > #{out} 2>&1") or raise "failed: #{cmd}\n#{File.read(out)}"
    end
  end

  def cleanup
    @pids.each_value do |pid|
      Process.kill("TERM", pid)
      Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
    @pids.clear
    %w[zebra isisd].each do |d|
      pid = File.read("#{@run}/#{d}.pid").to_i
      Process.kill("TERM", pid) if pid.positive?
    rescue Errno::ENOENT, Errno::ESRCH
      nil
    end
    %w[sim isisd frr].each { |n| system("ip netns del #{ns(n)} 2>/dev/null") }
    FileUtils.rm_rf([@run, @etc])
  end

  def sh(cmd)
    system(cmd, exception: true, %i[out err] => File::NULL)
  end
end
