# frozen_string_literal: true

module ISIS
  # The IEEE 802.2 LLC header that IS-IS uses on a LAN: DSAP and SSAP both
  # 0xFE, control 0x03 (unnumbered information). Three bytes in front of
  # the IS-IS PDU, inside an 802.3 frame.
  module Llc
    DSAP    = 0xFE
    SSAP    = 0xFE
    CONTROL = 0x03
    HEADER  = [DSAP, SSAP, CONTROL].pack("C3").freeze
    SIZE    = 3

    # Prefix the LLC header to an IS-IS PDU.
    def self.wrap(pdu)
      HEADER + pdu.b
    end

    # Strip the LLC header and return the PDU. Raises unless it is an
    # IS-IS LLC header.
    def self.unwrap(bytes)
      b = bytes.b
      raise ParseError, "short LLC header" if b.bytesize < SIZE

      dsap, ssap, = b.unpack("C3")
      unless dsap == DSAP && ssap == SSAP
        raise ParseError, format("not an IS-IS LLC header (dsap=0x%02x ssap=0x%02x)", dsap, ssap)
      end

      b[SIZE..] || ""
    end

    # True if the bytes begin with the IS-IS LLC SAPs.
    def self.isis?(bytes)
      b = bytes.b
      b.bytesize >= SIZE && b.getbyte(0) == DSAP && b.getbyte(1) == SSAP
    end
  end
end
