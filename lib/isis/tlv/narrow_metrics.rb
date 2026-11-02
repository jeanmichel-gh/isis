# frozen_string_literal: true

module ISIS
  class Tlv
    # The four original metric octets of one entry, default, delay, expense
    # and error, in that order, kept exactly as they arrived so reserved
    # bits replay. Each TLV that carries them says which octets have an
    # I/E bit, because the layouts differ:
    #
    # * TLV 2, RFC 1142 clause 9.8: every one of the four has I/E at bit 7.
    #   The default's bit 8 is reserved; the other three have S at bit 8.
    # * TLV 128, RFC 1195 section 5.3.4: only the default has I/E, "the
    #   metric type ... for all four TOS metrics"; bit 7 of the other three
    #   is reserved. The default's bit 8 is reserved, the others' is S.
    #
    # Bit 1 is the least significant (RFC 1142 clause 9.1), so bit 8 is
    # 0x80 and bit 7 is 0x40. S set means the metric is not supported: "If
    # this IS does not support this metric it shall set the bit S to 1".
    class NarrowMetrics
      VALUE = 0x3f
      IE = 0x40
      S = 0x80
      NAMES = %i[default delay expense error].freeze

      attr_reader :octets

      def initialize(octets)
        raise ArgumentError, "four metric octets, not #{octets.bytesize}" unless octets.bytesize == 4

        @octets = octets.b
      end

      # The octets for these field values. A delay, expense or error of nil
      # is unsupported, S set. +external+ sets I/E in each octet in
      # +ie_octets+, the indexes this TLV gives an I/E bit. +up_down+ sets
      # bit 8 of the default octet, which RFC 5302 section 2 makes the
      # up/down bit in TLVs 128 and 130; only those pass it, since in TLV 2
      # that bit is reserved.
      def self.build(metric:, ie_octets:, delay: nil, expense: nil, error: nil, external: false, up_down: false)
        values = [metric, delay, expense, error]
        octets = values.each_with_index.map do |v, i|
          raise ArgumentError, "the default metric is not optional" if v.nil? && i.zero?

          octet = v.nil? ? S : field(v, NAMES[i])
          octet |= IE if external && ie_octets.include?(i)
          octet |= S if up_down && i.zero?
          octet
        end
        new(octets.pack("C4"))
      end

      def self.field(value, name)
        n = Integer(value)
        raise ArgumentError, "#{name} metric #{n} does not fit in six bits" unless (0..VALUE).cover?(n)

        n
      end

      def default
        @octets.getbyte(0) & VALUE
      end

      # The delay, expense or error metric, or nil when S says it is not
      # supported.
      def value(name)
        i = NAMES.index(name)
        octet = @octets.getbyte(i)
        return octet & VALUE if i.zero?

        octet & S == 0 ? octet & VALUE : nil
      end

      def external?
        @octets.getbyte(0) & IE != 0
      end

      # Field values that build these octets again, if any do.
      def fields
        h = { metric: default }
        %i[delay expense error].each { |n| h[n] = value(n) unless value(n).nil? }
        h[:external] = true if external?
        h
      end

      # True when the field values say everything: building from them gives
      # these octets back, reserved bits and all.
      def canonical?(ie_octets, up_down: false)
        self.class.build(**fields, ie_octets: ie_octets, up_down: up_down).octets == @octets
      end

      def to_s
        parts = ["metric #{default}"]
        %i[delay expense error].each { |n| parts << "#{n} #{value(n)}" unless value(n).nil? }
        parts << "external" if external?
        parts.join(" ")
      end
    end
  end
end
