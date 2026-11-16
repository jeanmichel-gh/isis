# frozen_string_literal: true

# What routescope reads from isisd and isis4r-sim, **copied** from
# routescope, so this repository's tests hold its API to it with no
# routescope here (routescope docs/design/api-contract.md, part 3).
#
# Written by `rake vocabulary` in routescope on 2026-11-16, at e20935b
# with branch claude/sr-nodes-all on it (its SR nodes read each node's
# Router ID, SRLB and Node-SID): each method routescope's
# Isis4r and Isis4rSim drivers call, with the keys they read from its
# answer. "a.b" is key b of a; "[]" is each element of an array. A method
# with no keys is one whose answer routescope passes on whole, or whose
# success is all it reads.
#
# To refresh it: run `bundle exec rake vocabulary` in routescope and copy
# its "isisd" and "isis4r-sim" sections here, with the commit and date.
# test/unit/daemon/routescope_vocabulary_test.rb checks it.
module RoutescopeVocabulary
  ISISD = {
    "events.subscribe" => %w[],
    "policy.leak" => %w[],
    "policy.overload" => %w[],
    "policy.summaries" => %w[],
    "show.adjacencies" => %w[[].address [].areas [].hold [].hostname [].interface [].level [].state],
    "show.database" => %w[[].att [].checksum [].hostname [].length [].level [].lifetime [].lsp_id [].ol [].p [].purged [].self [].sequence],
    "show.labels" => %w[[].fec [].kind [].label [].level [].next_hops [].next_hops[].address [].next_hops[].interface [].next_hops[].label [].op],
    "show.overview" => %w[areas hostname lsps spf_runs system_id],
    "show.routes" => %w[[].level [].metric [].next_hops [].next_hops[].address [].next_hops[].interface [].next_hops[].label [].prefix [].sid [].up_down],
    "show.segment_routing" => %w[adj_sids adj_sids[].family adj_sids[].interface adj_sids[].label adj_sids[].neighbor enabled levels levels.2.nodes levels.2.nodes[].algorithms levels.2.nodes[].hostname levels.2.nodes[].label levels.2.nodes[].router_id levels.2.nodes[].sid levels.2.nodes[].srgb levels.2.nodes[].srlb levels.2.nodes[].system_id router_id srgb srlb],
    "show.topology" => %w[level nodes nodes[].attached nodes[].hostname nodes[].id nodes[].neighbors nodes[].neighbors[].id nodes[].neighbors[].metric nodes[].overload nodes[].prefixes nodes[].prefixes[].metric nodes[].prefixes[].prefix nodes[].reachable run]
  }.freeze

  ISIS4R_SIM = {
    "events.subscribe" => %w[],
    "policy.leak" => %w[],
    "policy.overload" => %w[],
    "policy.summaries" => %w[],
    "show.adjacencies" => %w[[].address [].areas [].hold [].hostname [].interface [].level [].state],
    "show.database" => %w[[].att [].checksum [].hostname [].length [].level [].lifetime [].lsp_id [].ol [].p [].purged [].self [].sequence],
    "show.labels" => %w[],
    "show.overview" => %w[areas hostname lsps spf_runs system_id],
    "show.routes" => %w[[].level [].metric [].next_hops [].next_hops[].address [].next_hops[].interface [].prefix [].up_down],
    "show.segment_routing" => %w[],
    "show.topology" => %w[],
    "sim.aging" => %w[],
    "sim.flush" => %w[],
    "sim.graph" => %w[nodes nodes[].grid nodes[].id],
    "sim.link.down" => %w[],
    "sim.link.flap" => %w[],
    "sim.link.metric" => %w[],
    "sim.link.toggle" => %w[],
    "sim.link.up" => %w[],
    "sim.neighbor.start" => %w[],
    "sim.neighbor.stop" => %w[],
    "sim.prefixes.advertise" => %w[],
    "sim.prefixes.withdraw" => %w[],
    "sim.refresh" => %w[],
    "sim.restore" => %w[],
    "sim.router.attached" => %w[],
    "sim.router.overload" => %w[],
    "sim.state" => %w[aging counts counts.systems generating interfaces interfaces[].hellos links links[].from links[].levels links[].metric links[].name links[].number links[].one_way links[].state links[].to metric_max metric_style systems systems[].attached systems[].groups systems[].levels systems[].lsps systems[].name systems[].overload systems[].prefixes systems[].simulator systems[].system_id systems[].withdrawn]
  }.freeze
end
