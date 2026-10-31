# frozen_string_literal: true

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
end
