# frozen_string_literal: true

# isis4r: build, parse and speak IS-IS. Entry point; requires everything.
#
# Today this is still the proof of concept: one L1 LAN adjacency formed
# with LAN Hellos over IEEE 802.3 and LLC, on the datalink-socket loopback
# backend with no privileges, or on a real interface with root. See
# CLAUDE.md for where it is going.

require "datalink"

require "isis/common"
require "isis/codepoints"
require "isis/link/llc"
require "isis/tlv/tlv"
require "isis/pdu/lan_hello"
require "isis/adjacency/adjacency"
require "isis/adjacency/circuit"
