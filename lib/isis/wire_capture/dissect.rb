# frozen_string_literal: true
require 'isis4r'

module ISIS
  module WireCapture
    module Dissect
      module_function

      def field(name, offset, length, value = nil, children = nil)
        result = { name: name, offset: offset, length: length }
        result[:value] = value unless value.nil?
        result[:children] = children if children && !children.empty?
        result
      end

      # The protocol parser owns meaning. This adapter adds frame offsets,
      # keeping undecodable and truncated bytes visible rather than dropping them.
      def frame(bytes)
        fields = []
        errors = []
        decoded = nil
        summary = 'IS-IS frame'
        begin
          raise ArgumentError, 'truncated Ethernet header' if bytes.bytesize < 14
          fields << field('Ethernet', 0, 14, nil, [
            field('destination', 0, 6, bytes[0, 6].unpack1('H*')),
            field('source', 6, 6, bytes[6, 6].unpack1('H*')),
            field('length', 12, 2, bytes[12, 2].unpack1('n'))
          ])
          at = 14
          # VLAN tags precede the 802.3 length and LLC header.
          while [0x8100, 0x88a8].include?(bytes[at - 2, 2].unpack1('n'))
            raise ArgumentError, 'truncated VLAN tag' if at + 4 > bytes.bytesize
            fields << field('VLAN', at, 4, bytes[at, 4].unpack1('H*'))
            at += 4
          end
          raise ArgumentError, 'not an IS-IS LLC frame' unless bytes[at, 3] == "\xfe\xfe\x03".b
          fields << field('LLC', at, 3, nil, %w[DSAP SSAP control].each_with_index.map { |n, i| field(n, at + i, 1, bytes.getbyte(at + i)) })
          at += 3
          payload = bytes.byteslice(at..)
          capture = ISIS::Capture.new(ISIS::Octets.new(payload))
          pdu = capture.pdu
          decoded = pdu.to_s
          summary = decoded
          plen = payload.bytesize - capture.tail.bytesize
          kids = []
          common = ['IRPD', 'length indicator', 'version extension', 'ID length', 'PDU type', 'version', 'reserved', 'maximum areas']
          [8, plen].min.times { |i| kids << field(common[i], at + i, 1, payload.getbyte(i)) }
          if pdu.is_a?(ISIS::Pdu::Layout)
            fixed = pdu.fixed_length
            raise ArgumentError, 'fixed header exceeds captured PDU' if fixed > plen
            kids << field('PDU fixed header', at + 8, fixed - 8, payload[8, fixed - 8].unpack1('H*')) if fixed > 8
            offset = fixed
            pdu.tlvs.each do |tlv|
              size = tlv.encode.bytesize
              raise ArgumentError, 'TLV exceeds captured PDU' if offset + size > plen
              value = payload[offset + 2, size - 2]
              children = [field('type', at + offset, 1, payload.getbyte(offset)), field('length', at + offset + 1, 1, payload.getbyte(offset + 1))]
              children << field('value', at + offset + 2, size - 2, value.unpack1('H*')) if size > 2
              kids << field(tlv.to_s, at + offset, size, nil, children)
              offset += size
            end
            kids << field('PDU trailing data', at + offset, plen - offset, payload[offset, plen - offset].unpack1('H*')) if offset < plen
          elsif plen > kids.size
            errors << 'IS-IS parser returned an unknown, malformed, or truncated PDU'
            kids << field('undecoded PDU data', at + kids.size, plen - kids.size, payload[kids.size, plen - kids.size].unpack1('H*'))
          end
          fields << field('IS-IS', at, plen, nil, kids)
          fields << field('frame padding', at + plen, capture.tail.bytesize, capture.tail.unpack1('H*')) unless capture.tail.empty?
        rescue StandardError => error
          errors << "IS-IS capture: #{error.class}: #{error.message}"
          covered = fields.sum { |f| f[:length] }
          fields << field('undecoded frame data', covered, bytes.bytesize - covered, bytes[covered..].unpack1('H*')) if covered < bytes.bytesize
        end
        { summary: summary, length: bytes.bytesize, fields: fields, errors: errors, decoded: decoded }
      end
    end
  end
end
