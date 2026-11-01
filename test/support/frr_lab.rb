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
  ISIS4R_ID = "0000.0000.0001"
  # What isis4r advertises in TLV 135: the link's subnet, and a prefix that
  # exists nowhere but in its LSP, so FRR can only have it from IS-IS.
  ISIS4R_PREFIXES = [{ prefix: "10.0.12.0/24", metric: 10 }, { prefix: "192.0.2.1/32", metric: 5 }].freeze

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
  end

  # Brings both sides up. +hello_interval+ and +hello_multiplier+ apply to
  # both, so the holding time is short and a lost neighbour shows quickly.
  # +isis4r+ overrides the isis4r circuit's settings, and +frr_interface+
  # adds lines under FRR's interface and +frr_router+ under its router isis.
  # +network+ is :point_to_point or :broadcast, for both sides. +level+ is
  # 1 or 2, which FRR and isis4r's LAN circuit run alone, or "1-2", which
  # both run at once: FRR as level-1-2, isis4r with a circuit per level.
  def start(hello_interval: 1, hello_multiplier: 3, isis4r: {}, frr_interface: [], frr_router: [],
            network: :point_to_point, level: 1)
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
    @network = network
    @level = level
    start_frr(hello_interval, hello_multiplier, frr_interface, frr_router)
    start_isis4r({ interface: "veth0", system_id: ISIS4R_ID, areas: ["49.0001"], ip_addresses: ["10.0.12.1"],
                   prefixes: ISIS4R_PREFIXES, network: network.to_s, level: level,
                   hello_interval: hello_interval, hello_multiplier: hello_multiplier }.merge(isis4r))
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

  # FRR's LSPs as `show isis database` lists them: LSP ID, sequence,
  # checksum, and whether it is a purge. FRR prints its own LSPs under its
  # hostname, so the hostname is written back as FRR's System ID. Measured
  # on FRR 8.4.4: an LSP with zero Remaining Lifetime shows its holdtime in
  # parentheses, "(1192)", the time left before the header goes.
  #
  # With +level+, only that level's section, which FRR heads "IS-IS
  # Level-1 link-state database:" or "Level-2".
  def frr_database(level = nil)
    section = nil
    vtysh("show isis database").lines.filter_map do |line|
      section = Regexp.last_match(1).to_i if line =~ /Level-(\d) link-state database/
      next if level && section != level
      next unless (m = line.match(/^(\S+)\.(\h\h)-(\h\h)\s+\*?\s+\d+\s+0x(\h{8})\s+0x(\h{4})\s+(\(?)\d+/))

      host, pseudonode, number, sequence, checksum, paren = m.captures
      system = host == @name ? FRR_ID : host
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
        current = blocks["#{host == @name ? FRR_ID : host}.#{pseudonode}-#{number}"] = +""
      elsif current && line.start_with?("  ")
        current << line
      else
        current = nil
      end
    end
    blocks
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

  def vtysh(cmd)
    # stdout only: vtysh warns on stderr about a missing vtysh.conf.
    out, = Open3.capture3("vtysh", "-N", @name, "-c", cmd)
    out
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
       isis circuit-type #{frr_level}
      #{@network == :broadcast ? '' : ' isis network point-to-point'}
       isis hello-interval #{hello_interval}
       isis hello-multiplier #{hello_multiplier}
      #{iface_lines.map { |l| " #{l}" }.join("\n")}
      router isis LAB
       net 49.0001.#{FRR_ID}.00
       is-type #{frr_level}
      #{router_lines.map { |l| " #{l}" }.join("\n")}
    CONF
    # zebra gets a file of its own: given isisd's, it rejects every IS-IS line.
    zebra_conf = File.join(@etc, "zebra.conf")
    File.write(zebra_conf, "hostname #{@name}\n")
    FileUtils.touch(File.join(@dir, "isisd.log"))
    sh "chown -R frr:frr #{@run} #{@etc} #{@dir}"
    { "zebra" => zebra_conf, "isisd" => conf }.each { |d, file| start_daemon(d, file) }
  end

  # A daemon that will not start says why on its own output, before it
  # forks, so keep that output and put it in the error.
  def start_daemon(daemon, file)
    out = File.join(@dir, "#{daemon}.start.log")
    cmd = "ip netns exec #{@frr_ns} #{FRR}/#{daemon} -N #{@name} -d -f #{file} -i #{@run}/#{daemon}.pid"
    return if system("#{cmd} > #{out} 2>&1")

    raise "failed (#{$?.exitstatus}): #{cmd}\n#{File.read(out)}"
  end

  def start_isis4r(config)
    File.write(File.join(@dir, "isis4r.json"), JSON.generate(config))
    @isis_pid = Process.spawn("ip", "netns", "exec", @isis_ns, RbConfig.ruby,
                              "#{ROOT}/test/support/isis_runner.rb", File.join(@dir, "isis4r.json"), state_file,
                              %i[out err] => File.join(@dir, "isis4r.log"))
  end

  def cleanup
    %w[isisd zebra].each do |d|
      pid_file = "#{@run}/#{d}.pid"
      next unless File.exist?(pid_file)

      begin
        Process.kill("TERM", File.read(pid_file).to_i)
      rescue Errno::ESRCH
        nil
      end
      File.delete(pid_file)
    end
    sleep 0.3
    [@frr_ns, @isis_ns].each { |ns| system("ip netns del #{ns} 2>/dev/null") }
  end

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}"
  end
end
