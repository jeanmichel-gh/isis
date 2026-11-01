# frozen_string_literal: true

module ISIS
  class Tlv
    # TLV 1, Area Addresses. RFC 1142 clause 9.5: "CODE 1", "LENGTH total
    # length of the value field", and a value that is a list of "Address
    # Length" octets each followed by that many octets of "Area Address".
    #
    # The address length is framing, so this class writes it and an
    # AreaAddress holds only the address octets. An entry whose length runs
    # past the value cannot be an area, so it and what follows are kept as
    # a tail and replayed.
    class AreaAddresses < Tlv
      TYPE = 1

      attr_accessor :areas, :tail

      # A list: ["49.0001"]. A hash only when something arrived unusual: a
      # tail, or a type octet that is not 1.
      def to_hash
        list = @areas.map(&:to_s)
        return list if @tail.empty? && !unusual_type

        h = { areas: list }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h[:type] = unusual_type if unusual_type
        h
      end

      def to_s
        note = @tail.empty? ? "" : ", tail of #{@tail.bytesize} octets"
        "Area Addresses #{@areas.join(', ')}#{note}"
      end

      private

      def encode_value
        out = ISIS.buffer
        @areas.each { |a| out << [a.encode.bytesize].pack("C") << a.encode }
        out << @tail
      end

      def parse(octets)
        value = read_frame(octets)
        @areas = []
        i = 0
        while i < value.bytesize
          len = value.getbyte(i)
          break if i + 1 + len > value.bytesize

          @areas << AreaAddress.new_ntop(value.byteslice(i + 1, len))
          i += 1 + len
        end
        @tail = value.byteslice(i..).b
      end

      # AreaAddresses.new("49.0001", "49.0002"), or one array of them.
      def from_fields(*areas)
        areas = areas.first if areas.size == 1 && areas.first.is_a?(Array)
        @areas = areas.map { |a| AreaAddress.new(a) }
        @tail = "".b
      end

      def from_hash(hash)
        from_fields(hash.fetch(:areas))
        @tail = [hash.fetch(:tail, "")].pack("H*").b
        @type = hash[:type]
      end
    end

    register(AreaAddresses::TYPE, :area_addresses, AreaAddresses)
  end
end
