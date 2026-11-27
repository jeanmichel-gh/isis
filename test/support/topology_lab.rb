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
# interface to the failure's neighbor, as isisd or as FRR's isisd. isisd
# logs at info, not debug: 33 of them logging every PDU in hex starve two
# CPUs. Needs
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
  # Hellos every second, held 10 s. With 3 s, the 33 routers of
  # ti_lfa_too_deep on GitHub's two CPUs lost adjacencies, and S's repair
  # never settled (#122); pinned to two CPUs here, the same.
  HELLO_MULTIPLIER = 10

  attr_reader :entry, :systems, :dir

  # +sender+ puts a host H behind the PLR, its eth "toS" at 10.9.0.2 on
  # the PLR's "toH" at 10.9.0.1, with a default route through the PLR.
  # +forwarding+ has the PLR's isisd install its routes, label routes and
  # backups in the kernel, the PLR forward IPv4 and take labels from H.
  def initialize(prefix, name, plr: :isisd, sender: false, forwarding: false)
    @prefix = prefix
    @entry = ISIS::Fault.topology(name)
    @systems = ISIS::Fault.topology_systems(name)
    @plr_kind = plr
    @sender = sender
    @forwarding = forwarding
    @dir = Dir.mktmpdir("isis4r-#{prefix}")
    @run = "/var/run/frr/#{prefix}"
    @etc = "/etc/frr/#{prefix}"
    @pids = {}
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
    link_sender if @sender
    prepare_forwarding if @forwarding
    @systems.each { |s| s == plr && @plr_kind == :frr ? start_frr(s) : start_isisd(s) }
    self
  end

  def sender_ns = "#{@prefix}-H"

  # Stops and resumes a system's isisd (SIGSTOP, SIGCONT), or an FRR
  # PLR's isisd and zebra: with the PLR's stopped, the kernel alone
  # forwards what reaches it.
  def freeze(name) = daemon_pids(name).each { Process.kill("STOP", _1) }
  def thaw(name) = daemon_pids(name).each { Process.kill("CONT", _1) }

  def daemon_pids(name)
    return [@pids.fetch(name)] unless name == plr && @plr_kind == :frr

    %w[isisd zebra].map { File.read("#{@run}/#{_1}.pid").to_i }
  end

  # The PLR's Adj-SID toward +neighbor+: isisd's own, or the lowest of
  # FRR's label routes that pop onto the link to it.
  def plr_adj_sid(neighbor)
    return adj_sid(plr, neighbor) unless @plr_kind == :frr

    iface = "to#{neighbor}"
    hop = `ip -n #{ns(neighbor)} -j addr show #{"to#{plr}"}`.then { JSON.parse(_1).first["addr_info"].first["local"] }
    JSON.parse(vtysh("show mpls table json")).filter_map do |label, e|
      next unless Array(e["nexthops"]).any? { _1["nexthop"] == hop && _1["outLabel"] == 3 }

      Integer(label)
    end.min or raise "no Adj-SID of #{plr} on #{iface}"
  end

  # Takes +to+'s end of the link from +from+ down, so +from+'s end loses
  # carrier.
  def far_end_down(from, to) = sh("ip -n #{ns(to)} link set to#{from} down")

  # "ip route get" in +name+'s namespace, its first line.
  def route_get(name, address) = `ip -n #{ns(name)} route get #{address}`.lines.first.to_s

  def mac(netns, interface) = JSON.parse(`ip -n #{netns} -j link show #{interface}`).first["address"]

  # Runs Ruby in +netns+ with isis4r's and datalink's library.
  def ruby_in(netns, code, out: nil)
    args = ["ip", "netns", "exec", netns, RbConfig.ruby, *$LOAD_PATH.flat_map { ["-I", _1] }, "-e", code]
    out ? Process.spawn(*args, %i[out err] => out) : system(*args, exception: true)
  end

  # What +netns+ receives on +interface+ while the block runs, not what
  # it sends: each frame as [ether_type, payload octets]. The capture
  # starts first and stops a second after the block.
  def capture(netns, interface)
    file = File.join(@dir, "capture-#{netns}-#{interface}.jsonl")
    code = <<~RUBY
      require "datalink"; require "json"
      $stdout.sync = true
      Datalink::Socket.open(#{interface.inspect}, recv_timeout: 0.2) do |s|
        loop do
          r = s.recv
          next if r.packet_type == :outgoing

          f = r.frame
          puts JSON.generate([f.ether_type, f.payload.unpack1("H*")])
        rescue Datalink::TimeoutError
          next
        end
      end
    RUBY
    pid = ruby_in(netns, code, out: file)
    sleep 1.5
    yield
    sleep 1
    Process.kill("TERM", pid)
    Process.wait(pid)
    File.readlines(file).filter_map do |l|
      type, hex = JSON.parse(l)
      [type, [hex].pack("H*")]
    rescue JSON::ParserError
      nil
    end
  end

  # A captured frame, read as the catalog's packets are built: the entry
  # its UDP source port names, the labels on it top first, its IP TTL;
  # or an ICMP error, its type and code and the entry it quotes. nil for
  # anything else (IS-IS, ARP).
  def self.read_frame(type, payload)
    labels = []
    if type == 0x8847
      stack = ISIS::Mpls::LabelStack.new(ISIS::Octets.new(payload.dup))
      labels = stack.labels
      payload = payload.byteslice((4 * labels.size)..)
    elsif type != 0x0800
      return nil
    end
    ihl = (payload.getbyte(0) & 0xf) * 4
    body = payload.byteslice(ihl..)
    case payload.getbyte(9)
    when 17
      { packet: ISIS::Fault.packet_named_by(body.unpack1("n")), labels: labels, ttl: payload.getbyte(8) }
    when 1
      quoted = body.byteslice(8..)
      port = quoted.byteslice((quoted.getbyte(0) & 0xf) * 4, 2).unpack1("n")
      { icmp: body.unpack("CC"), quotes: ISIS::Fault.packet_named_by(port) }
    end
  end

  # Sends +frames+, each [ether_type, payload], from H to the PLR.
  def send_from_sender(frames)
    dst = mac(ns(plr), "toH")
    src = mac(sender_ns, "toS")
    list = frames.map { |t, octets| [t, octets.unpack1("H*")] }
    ruby_in(sender_ns, <<~RUBY)
      require "datalink"
      Datalink::Socket.open("toS") do |s|
        #{list.inspect}.each do |type, hex|
          s.send(Datalink::Frame.new(dst: #{dst.inspect}, src: #{src.inspect}, ether_type: type, payload: [hex].pack("H*")))
          sleep 0.05
        end
      end
    RUBY
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
  def flooded? = unflooded.empty?

  # What keeps the lab from being whole: each isisd missing adjacencies,
  # with how many are up, and each LSP the PLR holds at another sequence
  # than its system's, as [held, own].
  def unflooded
    out = {}
    (@systems - [plr]).each do |n|
      up = isisd(n, "show.adjacencies").count { _1["state"] == "up" }
      out["#{n} adjacencies"] = "#{up} of #{interfaces(n).size}" if up < interfaces(n).size
    end
    return out unless out.empty?

    held = plr_sequences
    own_sequences.each { |n, seq| out["#{n} LSP"] = [held[n], seq] unless seq && held[n] == seq }
    out
  end

  # Waits until the PLR holds every system's LSP as the system made it,
  # and a route to every loopback, then reads the repair twice, 3 s apart,
  # flooding still whole, until both reads agree. An SPF on a database
  # still filling gives other answers: on real routers, an LSP can take
  # 5 s to cross a line of them.
  def settled_repair(timeout = 120)
    loopbacks = (@systems - [plr]).map { "10.255.0.#{number(_1)}/32" }
    deadline = Time.now + timeout
    readings = []
    while Time.now < deadline
      if wait_for(deadline - Time.now) { flooded? && (loopbacks - plr_prefixes).empty? }
        first = plr_repair
        sleep 3
        second = plr_repair
        return second if first == second && flooded?

        readings = [first, second]
      end
    end
    why = begin
      { unflooded: unflooded, missing_routes: loopbacks - plr_prefixes, last_readings: readings }
    rescue StandardError => e
      e.message
    end
    raise "#{plr}'s repair did not settle in #{timeout} s: #{why.inspect}\n#{report}"
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

  def link_sender
    sh "ip netns add #{sender_ns}"
    sh "ip link add toH netns #{ns(plr)} type veth peer name toS netns #{sender_ns}"
    sh "ip -n #{ns(plr)} addr add 10.9.0.1/24 dev toH"
    sh "ip -n #{sender_ns} addr add 10.9.0.2/24 dev toS"
    sh "ip -n #{ns(plr)} link set toH up"
    sh "ip -n #{sender_ns} link set lo up"
    sh "ip -n #{sender_ns} link set toS up"
    sh "ip -n #{sender_ns} route add default via 10.9.0.1"
  end

  # The PLR's kernel: a label table that holds every SRGB of the entry
  # (isisd checks it, Router::Host#mpls), IPv4 forwarding, and labels
  # taken from H, whose link isisd does not run on.
  def prepare_forwarding
    n = ns(plr)
    sh "ip netns exec #{n} sysctl -qw net.mpls.platform_labels=100000"
    sh "ip netns exec #{n} sysctl -qw net.ipv4.ip_forward=1"
    sh "ip netns exec #{n} sysctl -qw net.mpls.conf.toH.input=1" if @sender
  end

  def start_isisd(name)
    file = File.join(@dir, "#{name}.yml")
    File.write(file, isisd_config(name).to_yaml)
    @pids[name] = Process.spawn("ip", "netns", "exec", ns(name), RbConfig.ruby, "#{ROOT}/exe/isisd", "-c", file,
                                "-s", socket(name), "-l", "-", %i[out err] => File.join(@dir, "#{name}.log"))
  end

  # The isisd file of +name+, as a Hash.
  def isisd_config(name)
    failure_kind, neighbor = @entry[:failure]
    {
      "system_id" => system_id(name), "hostname" => name, "areas" => ["49.0001"], "level" => 1,
      "metric_style" => "wide", "minimum_lsp_interval" => 1, "forwarding" => @forwarding && name == plr,
      "overload" => @entry[:overloaded].include?(name),
      "segment_routing" => { "srgb" => [{ "start" => srgb(name), "size" => 1_000 }] },
      "prefixes" => [{ "prefix" => "10.255.0.#{number(name)}/32", "metric" => 0, "sid" => number(name) }],
      "interfaces" => interfaces(name).map do |iface, address, metric, peer|
        i = { "name" => iface, "ip_addresses" => [address], "metric" => metric, "hello_interval" => 1,
              "hello_multiplier" => HELLO_MULTIPLIER }
        name == plr && peer == neighbor ? i.merge("ti_lfa" => failure_kind.to_s) : i
      end
    }
  end

  # FRR 10.5.1 as the PLR: isisd and zebra, TI-LFA on the failure's
  # interface, node-protection for a node failure.
  def start_frr(name)
    FileUtils.mkdir_p([@run, @etc])
    conf = File.join(@etc, "frr.conf")
    File.write(conf, frr_conf(name))
    zebra = File.join(@etc, "zebra.conf")
    File.write(zebra, "hostname #{name}\n")
    FileUtils.touch(File.join(@dir, "#{name}-frr.log"))
    sh "chown -R frr:frr #{@run} #{@etc} #{@dir}"
    # Zebra's lines, link-params among them, go in through mgmtd, as
    # FrrLab's frr_zebra do.
    zebra_lines = frr_zebra_lines(name)
    daemons = { "zebra" => zebra, "isisd" => conf }
    daemons = { "mgmtd" => nil }.merge(daemons) unless zebra_lines.empty?
    daemons.each do |d, file|
      out = File.join(@dir, "#{d}.start.log")
      cmd = "ip netns exec #{ns(name)} #{FRR}/#{d} -N #{@prefix} -d #{"-f #{file} " if file}-i #{@run}/#{d}.pid"
      system("#{cmd} > #{out} 2>&1") or raise "failed: #{cmd}\n#{File.read(out)}"
    end
    return if zebra_lines.empty?

    Open3.capture3("ip", "netns", "exec", ns(name), "vtysh", "-N", @prefix, "-c", "configure",
                   *zebra_lines.flat_map { ["-c", _1] })
  end

  # FRR's file for +name+: its interfaces, then router isis.
  def frr_conf(name)
    <<~CONF
      hostname #{name}
      log file #{File.join(@dir, "#{name}-frr.log")} informational
      #{frr_global_lines(name).join("\n")}
      #{interfaces(name).map { |iface, _, metric, peer| frr_interface_lines(name, iface, metric, peer).join("\n") }.join("\n")}
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
      #{frr_router_lines(name).map { " #{_1}" }.join("\n")}
    CONF
  end

  def frr_global_lines(_name) = []
  def frr_zebra_lines(_name) = []
  def frr_router_lines(_name) = []

  # The stanza of +name+'s interface +iface+, TI-LFA on the failure's.
  def frr_interface_lines(_name, iface, metric, peer)
    failure_kind, neighbor = @entry[:failure]
    lines = ["interface #{iface}", " ip router isis LAB", " isis network point-to-point", " isis metric #{metric}",
             " isis hello-interval 1", " isis hello-multiplier #{HELLO_MULTIPLIER}"]
    if peer == neighbor
      lines << (failure_kind == :node ? " isis fast-reroute ti-lfa node-protection" : " isis fast-reroute ti-lfa")
    end
    lines
  end

  def cleanup
    @pids.each_value do |pid|
      Process.kill("CONT", pid)
      Process.kill("TERM", pid)
      Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
    @pids.clear
    %w[isisd zebra mgmtd].each do |d|
      f = "#{@run}/#{d}.pid"
      next unless File.exist?(f)

      begin
        Process.kill("TERM", File.read(f).to_i)
      rescue Errno::ESRCH
        nil
      end
    end
    sleep 0.3
    (@systems.map { ns(_1) } + [sender_ns]).each { |n| system("ip netns del #{n} 2>/dev/null") }
    FileUtils.rm_rf([@run, @etc])
  end

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}"
  end
end
