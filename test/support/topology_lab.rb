# frozen_string_literal: true

require "json"
require "socket"
require "yaml"
require "fileutils"
require "tmpdir"
require "open3"
require "rbconfig"
require_relative "frr_lab"

# A topology of the fault catalog (ISIS::Fault::TOPOLOGIES) on real
# routers: a network namespace per system, a veth pair per link, and
# exe/isisd in each, as the entry numbers them (Fault.topology_file):
# system N is 0000.0000.NNNN, advertises 10.255.0.N/32 with Prefix-SID
# index N, and has the SRGB 16000 + 1000 N. The PLR runs TI-LFA on its
# interface to the failure's neighbor, as isisd or as FRR's isisd. Needs
# what FrrLab needs; the tests that use it run only with ISIS_FRR=1.
#
#   lab = TopologyLab.new("t1", :ti_lfa_figure_1, plr: :frr).start
#   lab.wait_for { lab.plr_backup }
#   lab.stop
#
# The interface in X toward Y is "toY", and link K joins 10.1.K.1 at its
# first end to 10.1.K.2 at its second.
class TopologyLab
  FRR = FrrLab::FRR
  ROOT = FrrLab::ROOT

  attr_reader :entry, :systems, :dir

  def initialize(prefix, name, plr: :isisd)
    @prefix = prefix
    @entry = ISIS::Fault.topology(name)
    @systems = ISIS::Fault.topology_systems(name)
    @plr_kind = plr
    @dir = Dir.mktmpdir("isis4r-#{prefix}")
    @run = "/var/run/frr/#{prefix}"
    @etc = "/etc/frr/#{prefix}"
    @pids = []
  end

  def plr = @entry[:plr]
  def number(name) = @systems.index(name) + 1
  def system_id(name) = format("0000.0000.%04x", number(name))
  def srgb(name) = 16_000 + (1_000 * number(name))
  def ns(name) = "#{@prefix}-#{name}"
  def socket(name) = File.join(@dir, "#{name}.sock")

  # Each link: [a, b, metric, index].
  def links = @entry[:links].each_with_index.map { |(a, b, m), k| [a, b, Integer(m), k] }

  # The interfaces of +name+: [interface, address, metric, peer].
  def interfaces(name)
    links.filter_map do |a, b, m, k|
      if a == name then ["to#{b}", "10.1.#{k}.1", m, b]
      elsif b == name then ["to#{a}", "10.1.#{k}.2", m, a]
      end
    end
  end

  def start
    cleanup
    @systems.each { |s| sh "ip netns add #{ns(s)}" }
    @systems.each { |s| sh "ip -n #{ns(s)} link set lo up" }
    links.each do |a, b, _, k|
      sh "ip link add to#{b} netns #{ns(a)} type veth peer name to#{a} netns #{ns(b)}"
      sh "ip -n #{ns(a)} addr add 10.1.#{k}.1/24 dev to#{b}"
      sh "ip -n #{ns(b)} addr add 10.1.#{k}.2/24 dev to#{a}"
      sh "ip -n #{ns(a)} link set to#{b} up"
      sh "ip -n #{ns(b)} link set to#{a} up"
    end
    @systems.each { |s| sh "ip -n #{ns(s)} addr add 10.255.0.#{number(s)}/32 dev lo" }
    @systems.each { |s| s == plr && @plr_kind == :frr ? start_frr(s) : start_isisd(s) }
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

  # One isisd API call on +name+.
  def isisd(name, method, params = {})
    s = UNIXSocket.new(socket(name))
    s.write(JSON.generate(id: 1, method: method, params: params) + "\n")
    r = JSON.parse(s.gets)
    raise r["error"] if r["error"]

    r["result"]
  ensure
    s&.close
  end

  # The loopbacks the PLR has a route to.
  def plr_prefixes
    if @plr_kind == :frr then frr_level_routes("show isis route json").map { _1["prefix"] }
    else isisd(plr, "show.routes").map { _1["prefix"] }
    end
  end

  # Each isisd's own LSP Number 0, by name: its sequence number as the
  # system itself holds it.
  def own_sequences
    (@systems - [plr]).to_h do |n|
      own = isisd(n, "show.database", "level" => 1).find { _1["lsp_id"] == "#{system_id(n)}.00-00" }
      [n, own && own["sequence"]]
    end
  end

  # The PLR's copy of each system's LSP Number 0, by name.
  def plr_sequences
    if @plr_kind == :frr
      vtysh("show isis database").lines.filter_map do |line|
        m = line.match(/^(\S+)\.00-00\s+\*?\s+\d+\s+0x(\h{8})/) or next
        [m[1], m[2].hex]
      end.to_h
    else
      isisd(plr, "show.database", "level" => 1).filter_map do |e|
        next unless e["lsp_id"].end_with?(".00-00")

        [e["hostname"], e["sequence"]]
      end.to_h
    end
  end

  # Whether every isisd has all its adjacencies up, and the PLR holds
  # every system's LSP as that system last made it. A system's own LSP
  # names only the adjacencies up when it was made.
  def flooded?
    return false unless (@systems - [plr]).all? { |n| isisd(n, "show.adjacencies").count { _1["state"] == "up" } == interfaces(n).size }

    own = own_sequences
    held = plr_sequences
    own.all? { |n, seq| seq && held[n] == seq }
  end

  # Waits until the PLR holds every system's LSP as the system made it,
  # and a route to every loopback, then reads the repair twice, 3 s apart,
  # flooding still whole, until both reads agree. An SPF on a database
  # still filling gives other answers: on real routers, an LSP can take
  # 5 s to cross a line of them.
  def settled_repair(timeout = 120)
    loopbacks = (@systems - [plr]).map { "10.255.0.#{number(_1)}/32" }
    deadline = Time.now + timeout
    while Time.now < deadline
      if wait_for(deadline - Time.now) { flooded? && (loopbacks - plr_prefixes).empty? }
        first = plr_repair
        sleep 3
        second = plr_repair
        return second if first == second && flooded?
      end
    end
    raise "#{plr}'s repair did not settle:\n#{report}"
  end

  def destination_prefix = "10.255.0.#{number(@entry[:destination])}/32"

  # The PLR's route to the destination: isisd's show.routes row, or
  # FRR's backup from "show isis route backup json" with its route.
  def plr_route
    @plr_kind == :frr ? frr_route : isisd(plr, "show.routes").find { _1["prefix"] == destination_prefix }
  end

  # FRR's route to the destination and its backup: { "route" => the
  # routing table's entry, "backup" => the backup table's, or nil }.
  def frr_route
    route = frr_level_routes("show isis route json").find { _1["prefix"] == destination_prefix } or return nil
    { "route" => route, "backup" => frr_level_routes("show isis route backup json").find { _1["prefix"] == destination_prefix } }
  end

  # Adj-SID label of +from+ toward +to+, from +from+'s isisd.
  def adj_sid(from, to)
    isisd(from, "show.segment_routing")["adj_sids"].find { _1["neighbor"] == to && _1["family"] == "ipv4" }&.fetch("label")
  end

  # The labels RFC 9855 7.1 asks for the entry's expected repair, top
  # first: a Node-SID as its index in the first hop's SRGB, an Adj-SID as
  # its owner allocated it, then the destination's index in Q's SRGB
  # unless Q is the destination.
  def expected_labels
    e = @entry[:expect]
    labels = e[:segments].map do |kind, x, y|
      kind == :node ? srgb(e[:first_hop]) + number(x) : adj_sid(x, y)
    end
    labels << srgb(e[:q]) + number(@entry[:destination]) unless e[:q] == @entry[:destination]
    labels
  end

  # A label stack, top first, read back as the routers forward it, from
  # +first_hop+: a label in the current router's SRGB is a Node-SID,
  # [:node, the system of that index], and the packet goes on toward it;
  # any other is the current router's Adj-SID, [:adj, router, neighbor].
  # A label no one owns is [:unknown, label]. Every router but the PLR is
  # an isisd, so their Adj-SIDs are asked of them.
  def segments_of(labels, first_hop)
    at = first_hop
    labels.map do |label|
      base = srgb(at)
      if label >= base && label < base + 1_000 && (n = @systems[label - base - 1]) && label > base
        at = n
        [:node, n]
      elsif (to = isisd(at, "show.segment_routing")["adj_sids"].find { _1["label"] == label && _1["family"] == "ipv4" })
        from = at
        at = to["neighbor"]
        [:adj, from, at]
      else
        [:unknown, label]
      end
    end
  end

  # The PLR's repair to the destination, as segments_of reads it: the
  # first hop and the segments, or { unprotected: reason } or { ecmp: true }
  # from isisd, or { none: true } when FRR has no backup.
  def plr_repair
    r = plr_route or return nil
    if @plr_kind == :frr
      b = r["backup"] or return { none: true }
      hop = interfaces(plr).find { _1[0] == b["interface"] }&.last
      labels = b["label(s)"].to_s.split("/").filter_map { Integer(_1, exception: false) }
      { first_hop: hop, segments: segments_of(labels, hop) }
    elsif (b = r["backup"])
      return { ecmp: true } if b["ecmp"]

      hop = interfaces(plr).find { _1[0] == b["interface"] }&.last
      r = { first_hop: hop, case: b["case"]&.to_sym, segments: segments_of(b["labels"], hop) }
      b["fallback"] ? r.merge(fallback: true) : r
    elsif r["unprotected"]
      { unprotected: r["unprotected"].to_sym }
    end
  end

  def vtysh(cmd)
    # vtysh reads no configuration of its own here and says so on stderr.
    out, _err, status = Open3.capture3("ip", "netns", "exec", ns(plr), "vtysh", "-N", @prefix, "-c", cmd)
    raise "vtysh #{cmd} failed" unless status.success?

    out
  end

  def report
    logs = Dir[File.join(@dir, "*.log")].map { |f| "--- #{File.basename(f)}\n#{File.read(f).lines.last(15).join}" }
    logs.join("\n")
  end

  private

  def frr_level_routes(cmd)
    Array(JSON.parse(vtysh(cmd))).flat_map { |area| Array(area.dig("level-1", "ipv4")) }
  end

  def start_isisd(name)
    failure_kind, neighbor = @entry[:failure]
    config = {
      "system_id" => system_id(name), "hostname" => name, "areas" => ["49.0001"], "level" => 1,
      "metric_style" => "wide", "minimum_lsp_interval" => 1, "forwarding" => false,
      "overload" => @entry[:overloaded].include?(name),
      "segment_routing" => { "srgb" => [{ "start" => srgb(name), "size" => 1_000 }] },
      "prefixes" => [{ "prefix" => "10.255.0.#{number(name)}/32", "metric" => 0, "sid" => number(name) }],
      "interfaces" => interfaces(name).map do |iface, address, metric, peer|
        i = { "name" => iface, "ip_addresses" => [address], "metric" => metric, "hello_interval" => 1,
              "hello_multiplier" => 3 }
        name == plr && peer == neighbor ? i.merge("ti_lfa" => failure_kind.to_s) : i
      end
    }
    file = File.join(@dir, "#{name}.yml")
    File.write(file, config.to_yaml)
    @pids << Process.spawn("ip", "netns", "exec", ns(name), RbConfig.ruby, "#{ROOT}/exe/isisd", "-c", file,
                           "-s", socket(name), "-l", "-", "-d", %i[out err] => File.join(@dir, "#{name}.log"))
  end

  # FRR 10.5.1 as the PLR: isisd and zebra, TI-LFA on the failure's
  # interface, node-protection for a node failure.
  def start_frr(name)
    failure_kind, neighbor = @entry[:failure]
    FileUtils.mkdir_p([@run, @etc])
    stanzas = interfaces(name).map do |iface, _, metric, peer|
      lines = ["interface #{iface}", " ip router isis LAB", " isis network point-to-point", " isis metric #{metric}",
               " isis hello-interval 1", " isis hello-multiplier 3"]
      if peer == neighbor
        lines << (failure_kind == :node ? " isis fast-reroute ti-lfa node-protection" : " isis fast-reroute ti-lfa")
      end
      lines.join("\n")
    end
    conf = File.join(@etc, "frr.conf")
    File.write(conf, <<~CONF)
      hostname #{name}
      log file #{File.join(@dir, "#{name}-frr.log")} informational
      #{stanzas.join("\n")}
      interface lo
       ip router isis LAB
       isis passive
      router isis LAB
       net 49.0001.#{system_id(name)}.00
       is-type level-1
       metric-style wide
       lsp-gen-interval 1
       segment-routing on
       segment-routing global-block #{srgb(name)} #{srgb(name) + 999}
       segment-routing prefix 10.255.0.#{number(name)}/32 index #{number(name)}
    CONF
    zebra = File.join(@etc, "zebra.conf")
    File.write(zebra, "hostname #{name}\n")
    FileUtils.touch(File.join(@dir, "#{name}-frr.log"))
    sh "chown -R frr:frr #{@run} #{@etc} #{@dir}"
    { "zebra" => zebra, "isisd" => conf }.each do |d, file|
      out = File.join(@dir, "#{d}.start.log")
      cmd = "ip netns exec #{ns(name)} #{FRR}/#{d} -N #{@prefix} -d -f #{file} -i #{@run}/#{d}.pid"
      system("#{cmd} > #{out} 2>&1") or raise "failed: #{cmd}\n#{File.read(out)}"
    end
  end

  def cleanup
    @pids.each do |pid|
      Process.kill("TERM", pid)
      Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
    @pids.clear
    %w[isisd zebra].each do |d|
      f = "#{@run}/#{d}.pid"
      next unless File.exist?(f)

      begin
        Process.kill("TERM", File.read(f).to_i)
      rescue Errno::ESRCH
        nil
      end
    end
    sleep 0.3
    @systems.each { |s| system("ip netns del #{ns(s)} 2>/dev/null") }
    FileUtils.rm_rf([@run, @etc])
  end

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}"
  end
end
