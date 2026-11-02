# frozen_string_literal: true

require "json"
require "fileutils"
require "tmpdir"
require "open3"
require "rbconfig"

# FRR's isisd in one network namespace and isis4r in another, joined by a
# veth pair. After ospfv2's test/support/frr_lab.rb, with isisd in place of
# ospfd. Needs root, iproute2 and FRR (zebra, isisd, vtysh); the tests that
# use it run only with ISIS_FRR=1.
#
#   lab = FrrLab.new("t1").start
#   lab.wait_for { lab.frr_adjacency_state == "Up" && lab.isis4r_state == "up" }
#   lab.stop
#
# Both sides are Level 1, point to point, area 49.0001. FRR is
# 0000.0000.0002 at 10.0.12.2; isis4r is 0000.0000.0001 at 10.0.12.1.
class FrrLab
  FRR = "/usr/lib/frr"
  ROOT = File.expand_path("../..", __dir__)
  FRR_ID = "0000.0000.0002"
  # A second FRR, with frr2: in start, behind the first: 0000.0000.0003 at
  # 10.0.23.3, joined to the first FRR's veth1 at 10.0.23.2.
  FRR2_ID = "0000.0000.0003"
  ISIS4R_ID = "0000.0000.0001"
  # What isis4r advertises in TLV 135: the link's subnet, and a prefix that
  # exists nowhere but in its LSP, so FRR can only have it from IS-IS.
  ISIS4R_PREFIXES = [{ prefix: "10.0.12.0/24", metric: 10 }, { prefix: "192.0.2.1/32", metric: 5 }].freeze
  # With ipv6: in start, the link is 2001:db8:12::/64, isis4r ::1 and FRR
  # ::2, and isis4r advertises the link and a /128 that exists nowhere
  # else, in TLV 236.
  # The subnet of the host behind isis4r, with +host+.
  HOST_PREFIX = { prefix: "203.0.113.0/24", metric: 10 }.freeze
  HOST_PREFIX6 = { prefix: "2001:db8:203::/64", metric: 10 }.freeze
  ISIS4R_PREFIXES6 = [{ prefix: "2001:db8:12::/64", metric: 10 }, { prefix: "2001:db8:1::1/128", metric: 5 }].freeze

  def self.available?
    return [false, "set ISIS_FRR=1 to run the FRR interop tests"] unless ENV["ISIS_FRR"] == "1"
    return [false, "needs root for network namespaces"] unless Process.uid.zero?
    unless %w[zebra isisd].all? { |d| File.executable?("#{FRR}/#{d}") } && system("which vtysh > /dev/null")
      return [false, "needs FRR (zebra, isisd, vtysh)"]
    end
    return [false, "needs iproute2"] unless system("which ip > /dev/null")
    return [false, apparmor_refusal] if isisd_confined?

    [true, nil]
  end

  APPARMOR_PROFILES = "/sys/kernel/security/apparmor/profiles"

  # Ubuntu's apparmor package ships a profile for isisd (26.04 does; 24.04
  # does not). It allows only FRR's default paths, such as
  # /run/frr/isisd.pid and /etc/frr/isisd.conf, so isisd started with -N in
  # its own directories exits with "Can't create pid lock file ...
  # (Permission denied)", even when the directory is owned by frr. zebra has
  # no profile, so it starts and isisd does not.
  def self.isisd_confined?(profiles = APPARMOR_PROFILES)
    File.readable?(profiles) && File.foreach(profiles).any? { |l| l.start_with?("isisd (enforce)") }
  end

  def self.apparmor_refusal
    "AppArmor confines isisd to FRR's default paths, and the lab uses its own. " \
      "Unload the profile until reboot with: sudo apparmor_parser -R /etc/apparmor.d/isisd"
  end

  attr_reader :name, :dir

  def initialize(name)
    @name = name
    @frr_ns = "#{name}-frr"
    @isis_ns = "#{name}-isis4r"
    @dir = Dir.mktmpdir("isis4r-#{name}")
    @run = "/var/run/frr/#{name}"
    @etc = "/etc/frr/#{name}"
    @name2 = "#{name}2"
    @frr2_ns = "#{name}-frr2"
    @host_ns = "#{name}-host"
    @run2 = "/var/run/frr/#{@name2}"
    @etc2 = "/etc/frr/#{@name2}"
  end

  # Brings both sides up. +hello_interval+ and +hello_multiplier+ apply to
  # both, so the holding time is short and a lost neighbour shows quickly.
  # +isis4r+ overrides the isis4r circuit's settings, and +frr_interface+
  # adds lines under FRR's interface and +frr_router+ under its router isis.
  # +frr_loopback+, a prefix such as "198.51.100.2/32", goes on FRR's lo
  # and into IS-IS as a passive circuit.
  # +frr_is_type+ overrides the first FRR's is-type, which is otherwise
  # the lab's level.
  # +frr2+ adds a second FRR behind the first, on a point to point link:
  # { is_type: "level-2-only", area: "49.0002", loopback: "198.51.100.3/32",
  # interface: [lines], link_metric:, isis4r_link: { frr_metric:,
  # isis4r_metric: } }. link_metric is the metric of the link between the
  # two FRRs, on both its ends, FRR's default 10 without it. The
  # link runs the levels is_type names, on both its ends. With isis4r_link,
  # isis4r's veth1, 10.0.13.1, joins the second FRR's veth1, 10.0.13.3, as
  # well, at those metrics.
  # +ipv6+ runs IPv6 on the link as well, both sides, with
  # +frr_loopback6+, a prefix such as "2001:db8:ff::2/128", on FRR's lo.
  # +frr_connected+, a prefix such as "198.18.5.1/24", goes on ext0, one
  # end of a veth pair inside FRR's namespace that is not in IS-IS, for
  # FRR to redistribute as connected. (A dummy interface would do, but not
  # every kernel the lab runs on has the dummy type.)
  # +host+ puts a host behind isis4r: a namespace whose eth0, 203.0.113.2,
  # joins isis4r's host0, 203.0.113.1, with a default route through
  # isis4r, and with +ipv6+ 2001:db8:203::2 through 2001:db8:203::1.
  # isis4r advertises the host's subnet, installs its routes through the
  # netlink adapter, and forwards, so traffic between the host and FRR
  # goes through isis4r's kernel on isis4r's routes alone.
  # +network+ is :point_to_point or :broadcast, for both sides. +level+ is
  # 1 or 2, which FRR and isis4r's LAN circuit run alone, or "1-2", which
  # both run at once: FRR as level-1-2, isis4r with a circuit per level.
  def start(hello_interval: 1, hello_multiplier: 3, isis4r: {}, frr_interface: [], frr_router: [],
            network: :point_to_point, level: 1, frr_loopback: nil, frr_is_type: nil, frr2: nil,
            ipv6: false, frr_loopback6: nil, host: false, frr_connected: nil)
    cleanup
    sh "ip netns add #{@frr_ns}"
    sh "ip netns add #{@isis_ns}"
    sh "ip link add veth0 netns #{@isis_ns} type veth peer name veth0 netns #{@frr_ns}"
    sh "ip -n #{@isis_ns} addr add 10.0.12.1/24 dev veth0"
    sh "ip -n #{@frr_ns} addr add 10.0.12.2/24 dev veth0"
    [@isis_ns, @frr_ns].each do |ns|
      sh "ip -n #{ns} link set lo up"
      sh "ip -n #{ns} link set veth0 up"
    end
    sh "ip -n #{@frr_ns} addr add #{frr_loopback} dev lo" if frr_loopback
    if frr_connected
      sh "ip -n #{@frr_ns} link add ext0 type veth peer name ext1"
      sh "ip -n #{@frr_ns} addr add #{frr_connected} dev ext0"
      %w[ext0 ext1].each { |l| sh "ip -n #{@frr_ns} link set #{l} up" }
    end
    @ipv6 = ipv6
    @frr_loopback6 = frr_loopback6
    if ipv6
      sh "ip -n #{@isis_ns} -6 addr add 2001:db8:12::1/64 dev veth0 nodad"
      sh "ip -n #{@frr_ns} -6 addr add 2001:db8:12::2/64 dev veth0 nodad"
      sh "ip -n #{@frr_ns} -6 addr add #{frr_loopback6} dev lo" if frr_loopback6
      # The kernel gives each end its link-local address once the link is
      # up; isis4r reads its own when it starts, so wait for both.
      raise "no link-local address on veth0" unless wait_for(5) { link_local(@isis_ns) && link_local(@frr_ns) }
    end
    link_host(ipv6) if host
    @network = network
    @level = level
    @frr_loopback = frr_loopback
    @frr_is_type = frr_is_type
    @frr2 = frr2
    link_frr2 if frr2
    # A new namespace starts with forwarding off, and zebra leaves it so,
    # so the FRRs forward the host's traffic only when told to.
    if host
      [@frr_ns, (@frr2_ns if frr2)].compact.each do |ns|
        sh "ip netns exec #{ns} sysctl -qw net.ipv4.ip_forward=1"
        sh "ip netns exec #{ns} sysctl -qw net.ipv6.conf.all.forwarding=1" if ipv6
      end
    end
    start_frr(hello_interval, hello_multiplier, frr_interface, frr_router)
    start_frr2(hello_interval, hello_multiplier) if frr2
    extra = if (link = frr2&.dig(:isis4r_link))
              [{ interface: "veth1", ip_addresses: ["10.0.13.1"], metric: link.fetch(:isis4r_metric, 10) }]
            else
              []
            end
    prefixes = ISIS4R_PREFIXES + (host ? [HOST_PREFIX] : [])
    prefixes6 = ISIS4R_PREFIXES6 + (host ? [HOST_PREFIX6] : [])
    v6 = ipv6 ? { ipv6: true, ipv6_addresses: ["2001:db8:12::1"], ipv6_prefixes: prefixes6 } : {}
    start_isis4r({ interface: "veth0", system_id: ISIS4R_ID, areas: ["49.0001"], ip_addresses: ["10.0.12.1"],
                   prefixes: prefixes, network: network.to_s, level: level, **v6, forwarding: host,
                   hello_interval: hello_interval, hello_multiplier: hello_multiplier,
                   extra_interfaces: extra }.merge(isis4r))
    self
  end

  # Stops isis4r only, so FRR sees its neighbour go silent.
  def stop_isis4r
    return unless @isis_pid

    Process.kill("TERM", @isis_pid)
    Process.wait(@isis_pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  ensure
    @isis_pid = nil
  end

  # Stops FRR's isisd only, so isis4r sees its neighbour go silent.
  def stop_frr_isisd
    pid_file = "#{@run}/isisd.pid"
    Process.kill("TERM", File.read(pid_file).to_i) if File.exist?(pid_file)
  rescue Errno::ESRCH
    nil
  end

  # The link-local IPv6 address on veth0 in namespace +ns+, or nil.
  def link_local(ns)
    out, = Open3.capture3("ip", "-n", ns, "-6", "-o", "addr", "show", "dev", "veth0", "scope", "link")
    out[%r{inet6 (fe80::[0-9a-f:]+)/}, 1]
  end

  def isis4r_link_local = link_local(@isis_ns)
  def frr_link_local = link_local(@frr_ns)

  # Takes isis4r's link to the second FRR down, on isis4r's side.
  def isis4r_frr2_link_down
    sh "ip -n #{@isis_ns} link set veth1 down"
  end

  # The same link, taken down at the second FRR's end. isis4r's veth1
  # stays up and only loses carrier, and the kernel keeps a next hop on a
  # link without carrier (net.ipv4.conf.*.ignore_routes_with_linkdown is 0
  # by default), so only isis4r withdrawing it moves the traffic.
  def frr2_isis4r_link_down
    sh "ip -n #{@frr2_ns} link set veth1 down"
  end

  def stop
    stop_isis4r
  ensure
    cleanup
  end

  # ---- isis4r's side ----

  def isis4r_state_doc
    JSON.parse(File.read(state_file))
  rescue Errno::ENOENT, JSON::ParserError
    {}
  end

  # "down", "initializing" or "up".
  def isis4r_state
    isis4r_state_doc["state"]
  end

  # isis4r's state for +level+: with both levels running, the one under
  # "levels"; otherwise the whole document.
  def isis4r_level_doc(level = nil)
    doc = isis4r_state_doc
    level && doc["levels"] ? doc["levels"].fetch(level.to_s, {}) : doc
  end

  # isis4r's database, one hash per entry, keyed by LSP ID: the only
  # level's, or +level+'s when it runs both.
  def isis4r_database(level = nil)
    isis4r_level_doc(level).fetch("database", []).to_h { |e| [e["lsp_id"], e] }
  end

  # The routes isis4r's Decision Process computed, keyed by prefix: metric
  # and next hops, each an address and a circuit.
  def isis4r_routes(level = nil)
    isis4r_level_doc(level).fetch("routes", []).to_h { |r| [r["prefix"], r] }
  end

  # FRR's LSPs as `show isis database` lists them: LSP ID, sequence,
  # checksum, and whether it is a purge. FRR prints its own LSPs under its
  # hostname, so the hostname is written back as FRR's System ID. Measured
  # on FRR 8.4.4: an LSP with zero Remaining Lifetime shows its holdtime in
  # parentheses, "(1192)", the time left before the header goes.
  #
  # With +level+, only that level's section, which FRR heads "IS-IS
  # Level-1 link-state database:" or "Level-2".
  def frr_database(level = nil, router: @name)
    section = nil
    vtysh("show isis database", router: router).lines.filter_map do |line|
      section = Regexp.last_match(1).to_i if line =~ /Level-(\d) link-state database/
      next if level && section != level
      next unless (m = line.match(/^(\S+)\.(\h\h)-(\h\h)\s+\*?\s+\d+\s+0x(\h{8})\s+0x(\h{4})\s+(\(?)\d+/))

      host, pseudonode, number, sequence, checksum, paren = m.captures
      system = system_for(host)
      ["#{system}.#{pseudonode}-#{number}",
       { "sequence" => sequence.hex, "checksum" => checksum.hex, "purged" => paren == "(" }]
    end.to_h
  end

  # What FRR shows of each LSP in `show isis database detail`, the lines
  # under its header joined, keyed by LSP ID as frr_database keys it. For
  # an IS reachability line, FRR 8.4.4 prints "Extended Reachability:
  # 0000.0000.0001.01 (Metric: 10)".
  # With +level+, only that level's section, as for frr_database.
  def frr_database_detail(level = nil)
    blocks = {}
    current = nil
    section = nil
    vtysh("show isis database detail").each_line do |line|
      section = Regexp.last_match(1).to_i if line =~ /Level-(\d) link-state database/
      if level && section != level
        current = nil
      elsif (m = line.match(/^(\S+)\.(\h\h)-(\h\h)\s+\*?\s+\d+\s+0x\h{8}/))
        host, pseudonode, number = m.captures
        current = blocks["#{system_for(host)}.#{pseudonode}-#{number}"] = +""
      elsif current && line.start_with?("  ")
        current << line
      else
        current = nil
      end
    end
    blocks
  end

  # FRR's IS-IS routes from `show isis route`, keyed by prefix: metric,
  # interface and next hop, nil where FRR prints "-". Measured on FRR
  # 8.4.4, which has no json form of this command: one table per level,
  # headed "IS-IS L1 IPv4 routing table:", with rows of prefix, metric,
  # interface, next hop and labels.
  def frr_isis_routes(level = 1, router: @name)
    section = nil
    vtysh("show isis route", router: router).lines.filter_map do |line|
      section = Regexp.last_match(1).to_i if line =~ /IS-IS L(\d) IPv4 routing table/
      next unless section == level && (m = line.match(%r{^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+)\s+(\S+)\s+(\S+)}))

      prefix, metric, iface, next_hop = m.captures
      [prefix, { "metric" => metric.to_i, "interface" => iface == "-" ? nil : iface,
                 "next_hop" => next_hop == "-" ? nil : next_hop }]
    end.to_h
  end

  # Every next hop FRR's `show isis route` gives each prefix, as
  # [interface, address] pairs in FRR's order. Measured on FRR 8.4.4: an
  # equal cost route prints its further next hops on rows of their own,
  # with the prefix and metric columns blank.
  def frr_isis_next_hops(level = 1, router: @name)
    section = nil
    prefix = nil
    hops = Hash.new { |h, k| h[k] = [] }
    vtysh("show isis route", router: router).each_line do |line|
      section = Regexp.last_match(1).to_i if line =~ /IS-IS L(\d) IPv4 routing table/
      next unless section == level

      if (m = line.match(%r{^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+\d+\s+(\S+)\s+(\S+)}))
        prefix = m[1]
        hops[prefix] << [m[2], m[3]] unless m[2] == "-"
      elsif prefix && (m = line.match(/^\s{10,}(veth\S*|lo|eth\S*)\s+(\d+\.\d+\.\d+\.\d+)/))
        hops[prefix] << [m[1], m[2]]
      end
    end
    hops
  end

  # FRR's route to +prefix+ from `show ip route PREFIX json`: the first
  # entry, a Hash with "protocol", "installed" and "nexthops", or nil.
  def frr_route(prefix)
    frr_json("show ip route #{prefix}").fetch(prefix, []).first
  end

  def isis4r_log
    File.read(File.join(@dir, "isis4r.log"))
  rescue Errno::ENOENT
    ""
  end

  # ---- FRR's side ----

  # +router+ is the first FRR's name, the default, or frr2_name.
  def vtysh(cmd, router: @name)
    # stdout only: vtysh warns on stderr about a missing vtysh.conf.
    out, = Open3.capture3("vtysh", "-N", router, "-c", cmd)
    out
  end

  # The second FRR's name, for vtysh's router:.
  def frr2_name = @name2

  # A hostname FRR prints in place of a System ID, as the System ID. FRR
  # learns the other FRR's name from its Dynamic Hostname TLV; isis4r sends
  # none, so it prints as its System ID.
  def system_for(host)
    { @name => FRR_ID, @name2 => FRR2_ID }.fetch(host, host)
  end

  # Configuration lines for FRR's running daemon, under "configure".
  def vtysh_config(*lines)
    args = ["vtysh", "-N", @name, "-c", "configure"] + lines.flat_map { |l| ["-c", l] }
    out, = Open3.capture3(*args)
    out
  end

  def frr_json(cmd)
    JSON.parse(vtysh("#{cmd} json"))
  rescue JSON::ParserError
    {}
  end

  # FRR's adjacency state for isis4r on veth0, "Up", "Initializing" or
  # "Down", or nil when FRR has none. Read from the plain text of
  # `show isis neighbor`, whose layout is a system ID, the interface, the
  # level, the state, the holding time and the SNPA.
  def frr_adjacency_state
    line = vtysh("show isis neighbor").lines.find { |l| l.include?("veth0") }
    line&.split&.at(3)
  end

  # On a broadcast circuit: true when FRR says it is the DIS on veth0,
  # false when it says it is not, nil when it says neither. From the
  # "LAN Priority: 64, is DIS" line of `show isis interface detail`.
  def frr_is_dis?
    line = vtysh("show isis interface detail").lines.find { |l| l.include?("LAN Priority") }
    return nil unless line

    !line.include?("is not DIS") && line.include?("is DIS")
  end

  # The LAN ID FRR reports for isis4r's adjacency, from the "LAN id:" field
  # of `show isis neighbor detail`.
  def frr_lan_id
    vtysh("show isis neighbor detail")[/LAN id: (\S+)/, 1]
  end

  def frr_log
    File.read(File.join(@dir, "isisd.log"))
  rescue Errno::ENOENT
    ""
  end

  # Everything a failed test wants printed.
  def report
    <<~REPORT
      --- FRR: show isis neighbor
      #{vtysh('show isis neighbor')}
      --- FRR: show isis database detail
      #{vtysh('show isis database detail')}
      --- FRR: show ip route
      #{vtysh('show ip route')}
      --- FRR isisd log
      #{frr_log.lines.last(40).join}
      #{@frr2 ? "--- FRR2: show isis neighbor\n#{vtysh('show isis neighbor', router: @name2)}\n" \
                 "--- FRR2: show isis database\n#{vtysh('show isis database', router: @name2)}\n" \
                 "--- FRR2: show isis route\n#{vtysh('show isis route', router: @name2)}" : ''}
      --- isis4r state
      #{isis4r_state_doc}
      --- isis4r log
      #{isis4r_log.lines.last(60).join}
    REPORT
  end

  def wait_for(timeout = 30)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.25
    end
    true
  end

  # The routes the netlink adapter put in isis4r's kernel, as `ip route`
  # prints them: proto 187 is RTPROT_ISIS, "isis" in rt_protos, so it lists exactly
  # those. +family+ is "-4" or "-6".
  def isis4r_kernel_routes(family = "-4")
    `ip -n #{@isis_ns} #{family} route show proto 187`
  end

  # The kernel's route to +prefix+ in isis4r's namespace, as `ip route`
  # prints it: its line and any nexthop lines under it, whitespace
  # squeezed.
  def isis4r_kernel_route(prefix, family = "-4")
    out = `ip -n #{@isis_ns} #{family} route show #{prefix} proto 187`
    out.lines.map { |l| l.strip.squeeze(" ") }.reject(&:empty?)
  end

  # True when the host behind isis4r reaches +address+, by ping.
  def host_ping(address)
    raise "the lab needs ping, from iputils-ping, for the host's traffic" unless system("command -v ping >/dev/null")

    system("ip netns exec #{@host_ns} ping -c 1 -W 1 #{address} >/dev/null 2>&1")
  end

  private

  def state_file = File.join(@dir, "state.json")

  # FRR's word for the level the lab runs: level-1, level-2-only or
  # level-1-2.
  def frr_level
    { 1 => "level-1", 2 => "level-2-only", "1-2" => "level-1-2" }.fetch(@level)
  end

  def start_frr(hello_interval, hello_multiplier, iface_lines, router_lines)
    FileUtils.mkdir_p([@run, @etc])
    conf = File.join(@etc, "frr.conf")
    File.write(conf, <<~CONF)
      hostname #{@name}
      log file #{File.join(@dir, 'isisd.log')} debugging
      debug isis adj-packets
      interface veth0
       ip router isis LAB
      #{@ipv6 ? ' ipv6 router isis LAB' : ''}
       isis circuit-type #{frr_level}
      #{@network == :broadcast ? '' : ' isis network point-to-point'}
       isis hello-interval #{hello_interval}
       isis hello-multiplier #{hello_multiplier}
      #{iface_lines.map { |l| " #{l}" }.join("\n")}
      #{if @frr_loopback || @frr_loopback6
          ["interface lo", (" ip router isis LAB" if @frr_loopback), (" ipv6 router isis LAB" if @frr_loopback6),
           " isis passive"].compact.join("\n")
        end}
      #{@frr2 ? frr2_link_stanza("veth1", hello_interval, hello_multiplier, frr2_metric_lines) : ''}
      router isis LAB
       net 49.0001.#{FRR_ID}.00
       is-type #{@frr_is_type || frr_level}
      #{router_lines.map { |l| " #{l}" }.join("\n")}
    CONF
    # zebra gets a file of its own: given isisd's, it rejects every IS-IS line.
    zebra_conf = File.join(@etc, "zebra.conf")
    File.write(zebra_conf, "hostname #{@name}\n")
    FileUtils.touch(File.join(@dir, "isisd.log"))
    sh "chown -R frr:frr #{@run} #{@etc} #{@dir}"
    { "zebra" => zebra_conf, "isisd" => conf }.each { |d, file| start_daemon(d, file) }
  end

  # The second FRR's namespace and its link to the first's veth1.
  def link_frr2
    sh "ip netns add #{@frr2_ns}"
    sh "ip link add veth1 netns #{@frr_ns} type veth peer name veth0 netns #{@frr2_ns}"
    sh "ip -n #{@frr_ns} addr add 10.0.23.2/24 dev veth1"
    sh "ip -n #{@frr2_ns} addr add 10.0.23.3/24 dev veth0"
    sh "ip -n #{@frr_ns} link set veth1 up"
    %w[lo veth0].each { |l| sh "ip -n #{@frr2_ns} link set #{l} up" }
    sh "ip -n #{@frr2_ns} addr add #{@frr2[:loopback]} dev lo" if @frr2[:loopback]
    return unless @frr2[:isis4r_link]

    sh "ip link add veth1 netns #{@isis_ns} type veth peer name veth1 netns #{@frr2_ns}"
    sh "ip -n #{@isis_ns} addr add 10.0.13.1/24 dev veth1"
    sh "ip -n #{@frr2_ns} addr add 10.0.13.3/24 dev veth1"
    sh "ip -n #{@isis_ns} link set veth1 up"
    sh "ip -n #{@frr2_ns} link set veth1 up"
  end

  # One end of the link between the two FRRs, point to point, at the
  # levels the second FRR's is-type names.
  def frr2_link_stanza(iface, hello_interval, hello_multiplier, lines)
    (["interface #{iface}", " ip router isis LAB", " isis circuit-type #{@frr2.fetch(:is_type)}",
      " isis network point-to-point", " isis hello-interval #{hello_interval}",
      " isis hello-multiplier #{hello_multiplier}"] + lines.map { |l| " #{l}" }).join("\n")
  end

  def frr2_metric_lines
    @frr2[:link_metric] ? ["isis metric #{@frr2[:link_metric]}"] : []
  end

  def start_frr2(hello_interval, hello_multiplier)
    FileUtils.mkdir_p([@run2, @etc2])
    conf = File.join(@etc2, "frr.conf")
    File.write(conf, <<~CONF)
      hostname #{@name2}
      log file #{File.join(@dir, 'isisd2.log')} debugging
      #{frr2_link_stanza('veth0', hello_interval, hello_multiplier, frr2_metric_lines + @frr2.fetch(:interface, []))}
      #{@frr2[:loopback] ? "interface lo\n ip router isis LAB\n isis passive" : ''}
      #{if (link = @frr2[:isis4r_link])
          frr2_link_stanza('veth1', hello_interval, hello_multiplier, ["isis metric #{link.fetch(:frr_metric, 10)}"])
        end}
      router isis LAB
       net #{@frr2.fetch(:area, '49.0001')}.#{FRR2_ID}.00
       is-type #{@frr2.fetch(:is_type)}
    CONF
    zebra_conf = File.join(@etc2, "zebra.conf")
    File.write(zebra_conf, "hostname #{@name2}\n")
    FileUtils.touch(File.join(@dir, "isisd2.log"))
    sh "chown -R frr:frr #{@run2} #{@etc2} #{@dir}"
    { "zebra" => zebra_conf, "isisd" => conf }.each do |d, file|
      start_daemon(d, file, ns: @frr2_ns, name: @name2, run: @run2)
    end
  end

  # A daemon that will not start says why on its own output, before it
  # forks, so keep that output and put it in the error.
  def start_daemon(daemon, file, ns: @frr_ns, name: @name, run: @run)
    out = File.join(@dir, "#{name}-#{daemon}.start.log")
    cmd = "ip netns exec #{ns} #{FRR}/#{daemon} -N #{name} -d -f #{file} -i #{run}/#{daemon}.pid"
    return if system("#{cmd} > #{out} 2>&1")

    raise "failed (#{$?.exitstatus}): #{cmd}\n#{File.read(out)}"
  end

  def link_host(ipv6)
    sh "ip netns add #{@host_ns}"
    sh "ip link add host0 netns #{@isis_ns} type veth peer name eth0 netns #{@host_ns}"
    sh "ip -n #{@isis_ns} addr add 203.0.113.1/24 dev host0"
    sh "ip -n #{@host_ns} addr add 203.0.113.2/24 dev eth0"
    sh "ip -n #{@isis_ns} link set host0 up"
    sh "ip -n #{@host_ns} link set lo up"
    sh "ip -n #{@host_ns} link set eth0 up"
    sh "ip -n #{@host_ns} route add default via 203.0.113.1"
    sh "ip netns exec #{@isis_ns} sysctl -qw net.ipv4.ip_forward=1"
    return unless ipv6

    sh "ip -n #{@isis_ns} -6 addr add 2001:db8:203::1/64 dev host0 nodad"
    sh "ip -n #{@host_ns} -6 addr add 2001:db8:203::2/64 dev eth0 nodad"
    sh "ip -n #{@host_ns} -6 route add default via 2001:db8:203::1"
    sh "ip netns exec #{@isis_ns} sysctl -qw net.ipv6.conf.all.forwarding=1"
  end

  def start_isis4r(config)
    File.write(File.join(@dir, "isis4r.json"), JSON.generate(config))
    @isis_pid = Process.spawn("ip", "netns", "exec", @isis_ns, RbConfig.ruby,
                              "#{ROOT}/test/support/isis_runner.rb", File.join(@dir, "isis4r.json"), state_file,
                              %i[out err] => File.join(@dir, "isis4r.log"))
  end

  def cleanup
    [@run, @run2].product(%w[isisd zebra]).each do |run, d|
      pid_file = "#{run}/#{d}.pid"
      next unless File.exist?(pid_file)

      begin
        Process.kill("TERM", File.read(pid_file).to_i)
      rescue Errno::ESRCH
        nil
      end
      File.delete(pid_file)
    end
    sleep 0.3
    [@frr_ns, @frr2_ns, @isis_ns, @host_ns].each { |ns| system("ip netns del #{ns} 2>/dev/null") }
    # The configuration and run directories, so runs do not pile up under
    # /etc/frr and /var/run/frr.
    FileUtils.rm_rf([@run, @etc, @run2, @etc2])
  end

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}"
  end
end
