# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 10, Authentication Information. RFC 1142 clause 9.5: "CODE 10",
    # a one octet Authentication Type, "1 Cleartext Password", "255
    # Routeing Domain private authentication method", the rest reserved,
    # then an Authentication Value "determined by the value of the
    # authentication type". RFC 5304 section 2 adds type 54, HMAC-MD5, with
    # a 16 octet value, so a TLV length of 17.
    #
    # This class is only the TLV. The HMAC-MD5 value covers the whole PDU,
    # so the PDU computes it, after the lengths and before an LSP's
    # checksum: see Pdu::Layout. A value parsed here is kept as it arrived.
    #
    # The HMAC-MD5 value is a computed field, so its hash does not carry
    # it, and a hash rebuilds it as zeros for the PDU to fill. A cleartext
    # password is a field, and its hash carries it.
    class Authentication < Tlv
      TYPE = 10
      CLEARTEXT = 1
      HMAC_MD5 = 54
      HMAC_MD5_LENGTH = 16

      attr_accessor :auth_type, :value

      # True for an HMAC-MD5 value the PDU can compute: type 54 with the
      # 16 octets RFC 5304 gives it.
      def hmac_md5?
        @auth_type == HMAC_MD5 && @value.bytesize == HMAC_MD5_LENGTH
      end

      def to_hash
        h =
          if @auth_type.nil? then { value: "" }
          elsif hmac_md5? then { auth_type: HMAC_MD5 }
          elsif @auth_type == CLEARTEXT && @value.match?(/\A[[:print:]]*\z/n) then { auth_type: CLEARTEXT, password: @value.dup }
          else { auth_type: @auth_type, value: @value.unpack1("H*") }
          end
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        case @auth_type
        when nil then "Authentication, empty"
        when HMAC_MD5 then "Authentication HMAC-MD5 #{@value.unpack1('H*')}"
        when CLEARTEXT then "Authentication cleartext, #{@value.bytesize} octets"
        else "Authentication type #{@auth_type}, #{@value.bytesize} octets"
        end
      end

      private

      def encode_value
        return "".b if @auth_type.nil?

        [@auth_type].pack("C") + @value
      end

      def parse(octets)
        frame = read_frame(octets)
        @auth_type = frame.getbyte(0)
        @value = (frame.byteslice(1..) || "").b
      end

      # Authentication.new(:hmac_md5), Authentication.new(password: "secret"),
      # or Authentication.new(auth_type: 255, value: octets).
      def from_fields(kind = nil, password: nil, auth_type: nil, value: nil)
        if kind == :hmac_md5
          @auth_type = HMAC_MD5
          @value = ("\x00" * HMAC_MD5_LENGTH).b
        elsif password
          @auth_type = CLEARTEXT
          @value = password.b
        else
          @auth_type = auth_type.nil? ? nil : field(auth_type)
          @value = (value || "").b
        end
      end

      def from_hash(hash)
        if hash[:auth_type] == HMAC_MD5 && !hash.key?(:value)
          from_fields(:hmac_md5)
        elsif hash.key?(:password)
          from_fields(password: hash[:password])
        else
          from_fields(auth_type: hash[:auth_type], value: [hash.fetch(:value, "")].pack("H*"))
        end
        @type = hash[:type]
      end

      def field(n)
        n = Integer(n)
        raise ArgumentError, "authentication type #{n} does not fit in an octet" unless (0..255).cover?(n)

        n
      end
    end

    register(Authentication::TYPE, :authentication, Authentication)
  end
end
