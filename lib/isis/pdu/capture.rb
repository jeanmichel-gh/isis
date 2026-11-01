# frozen_string_literal: true

module ISIS
  # What a link delivered: one PDU, and whatever came after it.
  #
  # A PDU replays exactly the octets it consumed. Octets past its declared
  # end are not its own: link padding, capture slack, or something else.
  # They belong here, one level up, so that a PDU replays its slice and a
  # capture replays everything it was handed. CLAUDE.md, parse rule 7.
  class Capture
    include Node

    attr_reader :pdu, :tail

    def encode
      out = ISIS.buffer
      out << @pdu.encode << @tail
      out
    end

    def to_hash
      h = { pdu: @pdu.to_hash, pdu_class: @pdu.class.name }
      h[:tail] = @tail.unpack1("H*") unless @tail.empty?
      h
    end

    def to_s
      @tail.empty? ? @pdu.to_s : "#{@pdu}, then #{@tail.bytesize} octets after it"
    end

    private

    def parse(octets)
      @pdu = Pdu.factory(octets)
      @tail = octets.b
      octets.replace("")
    end

    def from_fields(pdu, tail = "")
      @pdu = pdu
      @tail = tail.b
    end

    def from_hash(hash)
      klass = Object.const_get(hash.fetch(:pdu_class))
      raise ArgumentError, "#{klass} is not a PDU class" unless klass.is_a?(Class) && klass <= Pdu

      from_fields(klass.new(hash.fetch(:pdu)), [hash.fetch(:tail, "")].pack("H*"))
    end
  end
end
