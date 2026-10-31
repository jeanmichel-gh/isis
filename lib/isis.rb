# frozen_string_literal: true

# A proof-of-concept IS-IS daemon built on datalink-socket.
#
# Scope: form a LAN adjacency using IS-IS Hello (IIH) PDUs over IEEE 802.3
# with an LLC header, sent to the AllL1ISs multicast. It runs over the
# datalink-socket loopback backend with no privileges, and over a real
# interface with root.
#
# This PoC deliberately hand-rolls the link-layer plumbing (LLC framing,
# the 802.3 length field, polling the socket). Once it works, the generic
# pieces are candidates to move down into datalink-socket. See the project
# roadmap.

require "datalink"

module ISIS
  # Intradomain Routing Protocol Discriminator (ISO 10589).
  IRPD = 0x83
  PROTOCOL_VERSION = 1

  # PDU types (low 5 bits of the type octet).
  L1_LAN_IIH = 15
  L2_LAN_IIH = 16
  P2P_IIH    = 17
  L1_LSP     = 18
  L2_LSP     = 20

  # TLV type codes used by a Hello.
  TLV_AREA_ADDRESSES      = 1
  TLV_IS_NEIGHBORS        = 6
  TLV_PADDING             = 8
  TLV_PROTOCOLS_SUPPORTED = 129

  # NLPID values for Protocols Supported.
  NLPID_IPV4 = 0xCC
  NLPID_IPV6 = 0x8E

  # Well-known destination MACs for IS-IS on a LAN.
  ALL_L1_ISS = "01:80:c2:00:00:14"
  ALL_L2_ISS = "01:80:c2:00:00:15"

  class Error < StandardError; end
  class ParseError < Error; end
end

require "isis/system_id"
require "isis/llc"
require "isis/tlv"
require "isis/pdu"
require "isis/adjacency"
require "isis/circuit"
