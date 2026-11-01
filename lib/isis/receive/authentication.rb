# frozen_string_literal: true

module ISIS
  module Receive
    # The receive policy's authentication step, shared by the circuits: RFC
    # 5304 HMAC-MD5 against a configured key, by the clause the circuit
    # names.
    module Authentication
      module_function

      # +tlvs+ with an HMAC-MD5 Authentication TLV in front when there is a
      # key. First is where FRR 8.4.4 puts it; RFC 5304 does not say.
      def keyed(tlvs, key)
        key ? [Tlv::Authentication.new(:hmac_md5)] + tlvs : tlvs
      end

      # Why a received PDU fails authentication under +key+, or nil. With no
      # key there is nothing to check. With one, clause +clause+: a PDU with
      # no Authentication Information "shall be discarded" (i), and one of a
      # type this system does not implement is "outside the scope" of the
      # clause (ii), so isis4r, configured for HMAC-MD5, refuses it too. RFC
      # 5304 section 2: a receiver "MUST discard the PDU if the
      # Authentication Value is incorrect".
      def refusal(pdu, key, clause)
        return nil if key.nil?

        unless pdu.tlvs.any? { |t| t.is_a?(Tlv::Authentication) }
          return "no Authentication Information, and a key is configured (#{clause} i)"
        end
        return "authentication is not HMAC-MD5, and isis4r is configured for it (#{clause} ii)" unless pdu.hmac_md5?
        return "the HMAC-MD5 digest is wrong for the configured key (RFC 5304 section 2)" unless pdu.authentic?(key)

        nil
      end
    end
  end
end
