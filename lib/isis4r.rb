# frozen_string_literal: true

# isis4r: build, parse and speak IS-IS. Entry point; requires everything.
#
# Today this is still the proof of concept: one L1 LAN adjacency formed
# with LAN Hellos over IEEE 802.3 and LLC, on the datalink-socket loopback
# backend with no privileges, or on a real interface with root. See
# CLAUDE.md for where it is going.

require "datalink"

require "isis/version"
require "isis/common"
require "isis/codepoints"
require "isis/runtime/clock"
require "isis/runtime/scheduler"
require "isis/runtime/log"
require "isis/link/llc"
require "isis/link/socket_transport"
require "isis/link/simulated_transport"
require "isis/tlv/tlv"
require "isis/tlv/area_addresses"
require "isis/tlv/padding"
require "isis/tlv/protocols_supported"
require "isis/tlv/ip_interface_addresses"
require "isis/tlv/three_way_adjacency"
require "isis/tlv/is_neighbors"
require "isis/tlv/lsp_entries"
require "isis/tlv/narrow_metrics"
require "isis/tlv/is_reachability"
require "isis/tlv/ip_internal_reachability"
require "isis/subtlv/subtlv"
require "isis/tlv/extended_ip_reachability"
require "isis/tlv/extended_is_reachability"
require "isis/pdu/pdu"
require "isis/pdu/circuit_type"
require "isis/pdu/psnp"
require "isis/pdu/lsp"
require "isis/pdu/csnp"
require "isis/pdu/p2p_hello"
require "isis/pdu/capture"
require "isis/pdu/lan_hello"
require "isis/database/database"
require "isis/database/originator"
require "isis/adjacency/adjacency"
require "isis/adjacency/circuit"
require "isis/adjacency/three_way"
require "isis/adjacency/p2p_circuit"
