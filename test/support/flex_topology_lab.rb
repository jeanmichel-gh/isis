# frozen_string_literal: true

require_relative "topology_lab"

# A flex-algo topology of the fault catalog (ISIS::Fault::
# FLEX_ALGO_TOPOLOGIES) on real routers, as TopologyLab runs TI-LFA's: a
# network namespace per system, a veth pair per link, exe/isisd in each,
# and S, the system that computes, either isisd or FRR's isisd.
#
# Each system N advertises 10.255.0.N/32 with Prefix-SID index N for
# algorithm 0 and 100 + N for algorithm 128, and has the SRGB
# 16000 + 1000 N. Every system takes part in 128 but those the entry
# leaves out; those the entry names advertise its FAD. A color is a bit
# position, named bN in the affinity map. A link's attributes go on both
# its ends, or the entry's second set on its second end.
#
#   lab = FlexTopologyLab.new("fa1", :fa_exclude_any, plr: :frr).start
#   lab.settled_flex
#   lab.stop
class FlexTopologyLab < TopologyLab
  K = ISIS::Fault::FLEX_ALGO

  def initialize(prefix, name, plr: :isisd)
    super(prefix, :ti_lfa_neighbor, plr: plr)
    @entry = flex_entry(name)
    @systems = @entry[:links].flat_map { |a, b,| [a, b] }.uniq
  end

  # The entry as TopologyLab reads one: S is the PLR, D the destination;
  # with a repair, S protects its link to the repair's neighbour.
  def flex_entry(name)
    e = ISIS::Fault.flex_topologies.find { _1[:name] == name } or raise ArgumentError, "unknown flex topology #{name}"
    repair = e[:expect][:repair]
    e.merge(plr: "S", destination: "D", overloaded: [], failure: repair && [:link, repair[:link]])
  end

  def k_label(at, name) = srgb(at) + 100 + number(name)
  def peer_of(interface) = interfaces(plr).find { _1[0] == interface }&.last
  def attributes(name, peer)
    a, b, _, attrs, back = @entry[:links].find { |x, y,| [x, y].sort == [name, peer].sort }
    attrs ||= {}
    name == a ? attrs : (back || attrs)
  end

  # Waits until S holds every LSP and a route to every loopback, then
  # reads S's algorithm 128 twice, 3 s apart, until both agree.
  def settled_flex(timeout = 120)
    loopbacks = (@systems - [plr]).map { "10.255.0.#{number(_1)}/32" }
    deadline = Time.now + timeout
    readings = []
    while Time.now < deadline
      if wait_for(deadline - Time.now) { flooded? && (loopbacks - plr_prefixes).empty? && frr_attributes_sent? }
        first = flex_reading
        sleep 3
        second = flex_reading
        return second if first == second && flooded?

        readings = [first, second]
      end
    end
    raise "#{plr}'s algorithm #{K} did not settle in #{timeout} s: #{readings.inspect}\n#{report}"
  end

  # Whether FRR as S sends its own LSP whole: an IS reachability entry
  # for each of its links, each with its attributes when it has them.
  # FRR's first LSPs have neither (seen on CI, #146).
  def frr_attributes_sent?
    return true unless @plr_kind == :frr

    links = vtysh("show isis database detail #{plr}.00-00").split("Extended Reachability:").drop(1)
    want = interfaces(plr).count { |*, peer| attributes(plr, peer).slice(:affinity, :delay, :te_metric).any? }
    links.size >= interfaces(plr).size &&
      links.count { _1.match?(/Link Delay|Traffic Engineering Metric|Admin Group/) } >= want
  end

  # S's algorithm 128, as the catalog's expect reads it: { taking_part:
  # false }; or the winner's name, and D's route as its first hops and
  # metric, or unreachable; and the repair, when the entry protects.
  def flex_reading
    @plr_kind == :frr ? frr_flex : isisd_flex
  end

  def isisd_flex
    algo = isisd(plr, "show.flex_algo")["levels"]["1"]["algorithms"].find { _1["algorithm"] == K }
    return { taking_part: false } unless algo && algo["participating"]

    out = { winner: name_of(algo.dig("winner", "origin")) }
    route = algo["routes"].find { _1["prefix"] == destination_prefix }
    if route
      out[:first_hops] = route["next_hops"].map { peer_of(_1["interface"]) }.sort
      out[:metric] = route["metric"]
    else
      out[:unreachable] = true
    end
    @entry[:failure] ? out.merge(repair: isisd_flex_repair) : out
  end

  # The backup of S's label route for D's Prefix-SID for 128: as
  # TopologyLab#plr_repair reads one.
  def isisd_flex_repair
    row = isisd(plr, "show.labels", "level" => 1).find { _1["label"] == k_label(plr, "D") } or return nil
    return { unprotected: row["unprotected"].to_sym } if row["unprotected"]

    b = row["backup"] or return { none: true }
    return { ecmp: true } if b["ecmp"]

    { first_hop: peer_of(b["interface"]), case: b["case"]&.to_sym,
      segments: segments_of(b["labels"], peer_of(b["interface"])) }
  end

  def name_of(system_id) = @systems.find { system_id(_1) == system_id }

  # As TopologyLab's, with algorithm 128's Node-SIDs: index 100 + N in a
  # router's SRGB is [:node, system N].
  def segments_of(labels, first_hop)
    at = first_hop
    labels.map do |label|
      index = label - srgb(at)
      if index > 100 && index < 1_000 && (n = @systems[index - 101])
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

  # FRR's, read from text, since FRR 10.5.1 gives neither in JSON: the
  # elected FAD's source and FRR's local state from `show isis flex-algo
  # 128`, and D's row in the routing table of `show isis route algorithm
  # 128`.
  def frr_flex
    fad = vtysh("show isis flex-algo #{K}")
    source = fad[/Source: (\h{4}\.\h{4}\.\h{4})/, 1]
    state = fad[/Local state: (.*?)\s*$/, 1]
    return { taking_part: false } unless source
    return { taking_part: false, winner: name_of(source), state: state } unless state == "enabled"

    out = { winner: name_of(source) }
    route = frr_algorithm_route(vtysh("show isis route algorithm #{K}"))
    if route then out.merge!(route)
    else out[:unreachable] = true
    end
    @entry[:failure] ? out.merge(repair: frr_flex_repair) : out
  end

  # D's row of the "IPv4 routing table" section: first hops and metric.
  # A further next hop of an equal cost route is a row of its own with
  # the prefix and metric blank.
  def self.algorithm_route(text, prefix)
    table = text.split("IPv4 routing table:", 2)[1] or return nil
    hops = []
    metric = nil
    table.each_line do |line|
      if (m = line.match(%r{^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+)\s+(\S+)\s+(\S+)}))
        break if metric

        next unless m[1] == prefix

        metric = Integer(m[2])
        hops << m[3]
      elsif metric && (m = line.match(/^\s{10,}(to\S+)\s+\d+\.\d+\.\d+\.\d+/))
        hops << m[1]
      end
    end
    metric && { interfaces: hops, metric: metric }
  end

  def frr_algorithm_route(text)
    r = self.class.algorithm_route(text, destination_prefix) or return nil
    { first_hops: r[:interfaces].map { peer_of(_1) }.sort, metric: r[:metric] }
  end

  # FRR's backup for D's label route in 128, from the label table: the
  # backup next hop and its labels, if FRR has one.
  def frr_flex_repair
    e = JSON.parse(vtysh("show mpls table json"))[k_label(plr, "D").to_s] or return nil
    b = Array(e["backupNexthops"]).first or return { none: true }
    hop = peer_of(b["interface"])
    { first_hop: hop, segments: segments_of(Array(b["outLabelStack"]).reject { _1 == 3 }, hop) }
  end

  private

  def color_names(bits) = Array(bits).map { "b#{_1}" }

  def flex_config(name)
    return nil if @entry[:not_taking_part].include?(name)

    fad = @entry[:fads][name] or return [{ "algorithm" => K, "advertise" => false }]
    c = { "algorithm" => K, "priority" => fad.fetch(:priority, 128) }
    c["metric_type"] = fad[:metric_type] if fad[:metric_type]
    Array(fad[:subtlvs]).each do |s|
      key, value = s.first
      case key
      when :fad_exclude_admin_group then c["exclude_any"] = color_names(value[:groups])
      when :fad_include_any_admin_group then c["include_any"] = color_names(value[:groups])
      when :fad_include_all_admin_group then c["include_all"] = color_names(value[:groups])
      when :fad_exclude_srlg then c["exclude_srlg"] = value[:srlgs]
      else raise ArgumentError, "FlexTopologyLab has no isisd key for #{key}"
      end
    end
    [c]
  end

  # Every color the entry names, on a link or in a FAD.
  def used_colors
    on_links = @entry[:links].flat_map { |_, _, _, attrs, back| [attrs, back].compact.flat_map { Array(_1[:affinity]) } }
    in_fads = @entry[:fads].values.flat_map { |f| Array(f[:subtlvs]).flat_map { Array(_1.values.first[:groups]) } }
    (on_links + in_fads).uniq.sort
  end

  def isisd_config(name)
    config = super
    flex = flex_config(name)
    config["affinity_map"] = used_colors.to_h { ["b#{_1}", _1] } unless used_colors.empty?
    if flex
      config["flex_algo"] = flex
      config["prefixes"].first["algorithm_sids"] = { K => 100 + number(name) }
    end
    config["interfaces"].each do |i|
      peer = i["name"].delete_prefix("to")
      a = attributes(name, peer)
      i["affinity"] = color_names(a[:affinity]) if a[:affinity]
      i["delay"] = a[:delay] if a[:delay]
      i["te_metric"] = a[:te_metric] if a[:te_metric]
      i["srlg"] = a[:srlg] if a[:srlg]
    end
    config
  end

  # FRR as S: the colors, each interface's link-params, and algorithm
  # 128 taken part in, with S's Prefix-SID for it. S advertises no FAD
  # in any entry.
  def frr_global_lines(_name) = used_colors.map { "affinity-map b#{_1} bit-position #{_1}" }

  # Each interface's link-params, which are zebra's: its affinity, TE
  # metric and delay.
  def frr_zebra_lines(name)
    frr_global_lines(name) + interfaces(name).flat_map do |iface, _, _, peer|
      a = attributes(name, peer)
      params = []
      params << "  metric #{a[:te_metric]}" if a[:te_metric]
      params << "  delay #{a[:delay]} min #{a[:delay]} max #{a[:delay]}" if a[:delay]
      params << "  affinity #{color_names(a[:affinity]).join(' ')}" if a[:affinity]
      params.empty? ? [] : ["interface #{iface}", "link-params", *params.map(&:strip), "exit-link-params", "exit"]
    end
  end

  def frr_router_lines(name)
    raise ArgumentError, "FlexTopologyLab: FRR as S takes part" if @entry[:not_taking_part].include?(name)

    ["mpls-te on", "mpls-te router-address 10.255.0.#{number(name)}",
     "segment-routing prefix 10.255.0.#{number(name)}/32 algorithm #{K} index #{100 + number(name)}",
     "flex-algo #{K}", " dataplane sr-mpls", " exit"]
  end
end
