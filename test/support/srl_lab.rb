# frozen_string_literal: true

require "json"
require "fileutils"
require "tmpdir"
require "open3"
require "rbconfig"

# Nokia SR Linux in a container that containerlab runs, and isis4r in a
# network namespace, joined by a veth pair: the second independent IS-IS
# implementation the gates are shown against, beside FRR (FrrLab).
# CLAUDE.md, "Labs and interop", says why SR Linux.
#
# containerlab makes the pair: ethernet-1/1 inside the container, and a
# host end it names, which the lab moves into isis4r's namespace as veth0.
# Needs root, docker, containerlab and iproute2; the tests that use it run
# only with ISIS_SRL=1. The image is ISIS_SRL_IMAGE, or IMAGE below.
#
#   lab = SrlLab.new("t1").start
#   lab.wait_for { lab.srl_adjacency_state == "up" && lab.isis4r_state == "up" }
#   lab.stop
#
# Both sides are Level 1, point to point, area 49.0001, wide metrics. SR
# Linux is 0000.0000.0002 at 10.0.12.2 with 198.51.100.2/32 on lo0;
# isis4r is 0000.0000.0001 at 10.0.12.1.
class SrlLab
  IMAGE = ENV.fetch("ISIS_SRL_IMAGE", "ghcr.io/nokia/srlinux:26.7.2")
  ROOT = File.expand_path("../..", __dir__)
  SRL_ID = "0000.0000.0002"
  ISIS4R_ID = "0000.0000.0001"
  SRL_LOOPBACK = "198.51.100.2/32"
  # The metric SR Linux puts on its end of the link, set rather than left
  # to its default so the test does not depend on one.
  SRL_LINK_METRIC = 10
  # What isis4r advertises in TLV 135, as FrrLab does: the link's subnet,
  # and a prefix that exists nowhere but in its LSP.
  ISIS4R_PREFIXES = [{ prefix: "10.0.12.0/24", metric: 10 }, { prefix: "192.0.2.1/32", metric: 5 }].freeze

  def self.available?
    return [false, "set ISIS_SRL=1 to run the SR Linux interop tests"] unless ENV["ISIS_SRL"] == "1"
    return [false, "needs root for network namespaces and containerlab"] unless Process.uid.zero?
    %w[containerlab docker ip].each do |tool|
      return [false, "needs #{tool}"] unless system("which #{tool} > /dev/null")
    end

    [true, nil]
  end

  attr_reader :name, :dir

  def initialize(name)
    @name = name
    @lab = "isis4r-#{name}"
    @container = "clab-#{@lab}-srl"
    # containerlab's name for the host end of the pair; at most 15
    # characters, the kernel's limit on an interface name.
    @host_link = "#{name}h"[0, 15]
    @isis_ns = "#{name}-isis4r"
    @dir = Dir.mktmpdir("isis4r-#{name}")
  end

  # Brings both sides up. +hello_interval+ and +hello_multiplier+ apply to
  # both. +isis4r+ overrides the isis4r circuit's settings.
  def start(hello_interval: 1, hello_multiplier: 3, isis4r: {})
    cleanup
    File.write(topology_file, topology)
    sh "containerlab deploy -t #{topology_file} --reconfigure > #{File.join(@dir, 'containerlab.log')} 2>&1"
    sh "ip netns add #{@isis_ns}"
    sh "ip link set #{@host_link} netns #{@isis_ns}"
    sh "ip -n #{@isis_ns} link set #{@host_link} name veth0"
    sh "ip -n #{@isis_ns} addr add 10.0.12.1/24 dev veth0"
    sh "ip -n #{@isis_ns} link set lo up"
    sh "ip -n #{@isis_ns} link set veth0 up"
    configure_srl(hello_interval, hello_multiplier)
    start_isis4r({ interface: "veth0", system_id: ISIS4R_ID, areas: ["49.0001"], ip_addresses: ["10.0.12.1"],
                   prefixes: ISIS4R_PREFIXES, network: "point_to_point", level: 1, forwarding: false,
                   hello_interval: hello_interval, hello_multiplier: hello_multiplier,
                   extra_interfaces: [] }.merge(isis4r))
    self
  end

  def stop_isis4r
    return unless @isis_pid

    Process.kill("TERM", @isis_pid)
    Process.wait(@isis_pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  ensure
    @isis_pid = nil
  end

  def stop
    stop_isis4r
  ensure
    cleanup
  end

  def wait_for(timeout = 30)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.25
    end
    true
  end

  # ---- isis4r's side, read as FrrLab reads it ----

  def isis4r_state_doc
    JSON.parse(File.read(state_file))
  rescue Errno::ENOENT, JSON::ParserError
    {}
  end

  def isis4r_state = isis4r_state_doc["state"]

  def isis4r_database
    isis4r_state_doc.fetch("database", []).to_h { |e| [e["lsp_id"], e] }
  end

  def isis4r_routes
    isis4r_state_doc.fetch("routes", []).to_h { |r| [r["prefix"], r] }
  end

  def isis4r_log
    File.read(File.join(@dir, "isis4r.log"))
  rescue Errno::ENOENT
    ""
  end

  # ---- SR Linux's side ----

  # sr_cli in the container, with the output as text. A command ending in
  # "| as json" gives JSON.
  def sr_cli(command)
    out, = Open3.capture2e("docker", "exec", @container, "sr_cli", "-d", command)
    out
  end

  def sr_json(command)
    JSON.parse(sr_cli("#{command} | as json"))
  rescue JSON::ParserError
    {}
  end

  # The rows of a `show network-instance default protocols isis ...`
  # table, such as "adjacencybrief" or "databasebrief". Measured on SR
  # Linux 26.7.2: the JSON form keeps the table's column headings as keys,
  # "Lsp Id", "Sequence" and "Checksum" in decimal, under
  # "isis summary" / "instance".
  def srl_show_rows(what, table)
    doc = sr_json("show network-instance default protocols isis #{what}")
    doc.fetch("isis summary", []).flat_map { |s| s.fetch("instance", []) }.flat_map { |i| i.fetch(table, []) }
  end

  # "up", or another state, of SR Linux's adjacency with isis4r; nil with none.
  def srl_adjacency_state
    srl_show_rows("adjacency", "adjacencybrief").find { |a| a["Neighbor System Id"] == ISIS4R_ID }&.fetch("State")
  end

  # SR Linux's LSPs, keyed by LSP ID: sequence and checksum.
  def srl_database
    srl_show_rows("database", "databasebrief").to_h do |e|
      [e["Lsp Id"], { "sequence" => e["Sequence"], "checksum" => e["Checksum"] }]
    end
  end

  # SR Linux's IPv4 route to +prefix+ from its route table's state: the
  # route-type, metric, whether it is active, and the next hops' addresses,
  # found through its next hop group. nil with no route.
  def srl_route(prefix)
    table = sr_json("info from state network-instance default route-table")
    route = table.dig("ipv4-unicast", "route")&.find { |r| r["ipv4-prefix"] == prefix }
    return nil unless route

    group = table.fetch("next-hop-group", []).find { |g| g["index"] == route["next-hop-group"] }
    ids = group ? group.fetch("next-hop", []).map { |n| n["next-hop"] } : []
    hops = table.fetch("next-hop", []).select { |n| ids.include?(n["index"]) }.filter_map { |n| n["ip-address"] }
    { "route_type" => route["route-type"], "metric" => route["metric"], "active" => route["active"],
      "next_hops" => hops }
  end

  # Everything a failed test wants printed.
  def report
    <<~REPORT
      --- SR Linux: show isis adjacency
      #{sr_cli('show network-instance default protocols isis adjacency')}
      --- SR Linux: show isis database
      #{sr_cli('show network-instance default protocols isis database')}
      --- SR Linux: show route-table
      #{sr_cli('show network-instance default route-table')}
      --- isis4r state
      #{isis4r_state_doc}
      --- isis4r log
      #{isis4r_log.lines.last(60).join}
    REPORT
  end

  private

  def topology_file = File.join(@dir, "#{@lab}.clab.yml")
  def state_file = File.join(@dir, "state.json")

  def topology
    <<~YAML
      name: #{@lab}
      topology:
        nodes:
          srl:
            kind: nokia_srlinux
            image: #{IMAGE}
        links:
          - endpoints: ["srl:e1-1", "host:#{@host_link}"]
    YAML
  end

  # SR Linux's configuration, as sr_cli set commands, committed once
  # containerlab says the node is ready. Measured on 26.7.2.
  def configure_srl(hello_interval, hello_multiplier)
    isis = "set / network-instance default protocols isis instance main"
    lines = [
      "set / interface ethernet-1/1 admin-state enable",
      "set / interface ethernet-1/1 subinterface 0 admin-state enable",
      "set / interface ethernet-1/1 subinterface 0 ipv4 admin-state enable",
      "set / interface ethernet-1/1 subinterface 0 ipv4 address 10.0.12.2/24",
      "set / interface lo0 subinterface 0 admin-state enable",
      "set / interface lo0 subinterface 0 ipv4 admin-state enable",
      "set / interface lo0 subinterface 0 ipv4 address #{SRL_LOOPBACK}",
      "set / network-instance default interface ethernet-1/1.0",
      "set / network-instance default interface lo0.0",
      "#{isis} admin-state enable",
      "#{isis} level-capability L1",
      "#{isis} net [ 49.0001.#{SRL_ID}.00 ]",
      "#{isis} ipv4-unicast admin-state enable",
      "#{isis} level 1 metric-style wide",
      "#{isis} interface ethernet-1/1.0 admin-state enable",
      "#{isis} interface ethernet-1/1.0 circuit-type point-to-point",
      "#{isis} interface ethernet-1/1.0 ipv4-unicast admin-state enable",
      "#{isis} interface ethernet-1/1.0 level 1 metric #{SRL_LINK_METRIC}",
      "#{isis} interface ethernet-1/1.0 level 1 timers hello-interval #{hello_interval}",
      "#{isis} interface ethernet-1/1.0 level 1 timers hello-multiplier #{hello_multiplier}",
      "#{isis} interface lo0.0 admin-state enable",
      "#{isis} interface lo0.0 passive true",
      "#{isis} interface lo0.0 ipv4-unicast admin-state enable"
    ]
    out, status = Open3.capture2e("docker", "exec", "-i", @container, "sr_cli", "-ed", "--post", "commit now",
                                  stdin_data: lines.join("\n"))
    raise "SR Linux refused its configuration:\n#{out}" unless status.success? && out.include?("committed")
  end

  def start_isis4r(config)
    File.write(File.join(@dir, "isis4r.json"), JSON.generate(config))
    @isis_pid = Process.spawn("ip", "netns", "exec", @isis_ns, RbConfig.ruby,
                              "#{ROOT}/test/support/isis_runner.rb", File.join(@dir, "isis4r.json"), state_file,
                              %i[out err] => File.join(@dir, "isis4r.log"))
  end

  def cleanup
    system("containerlab destroy -t #{topology_file} --cleanup > /dev/null 2>&1") if File.exist?(topology_file)
    system("ip netns del #{@isis_ns} 2>/dev/null")
  end

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}\n#{File.read(File.join(@dir, 'containerlab.log')) rescue ''}"
  end
end
