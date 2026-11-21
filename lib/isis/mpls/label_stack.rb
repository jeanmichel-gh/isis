# frozen_string_literal: true

module ISIS
  module Mpls
    # An MPLS label stack, RFC 3032 section 2.1: "a sequence of 'label
    # stack entries'. Each label stack entry is represented by 4 octets":
    # Label, 20 bits; Exp, 3 bits; S, "Bottom of Stack, 1 bit"; TTL, 8
    # bits. "The top of the label stack appears earliest in the packet",
    # and S "is set to one for the last entry in the label stack".
    #
    # Built the four ways of docs/building-objects.md:
    #
    #   LabelStack.new(16005, 16007)        top first, S on the last, Exp and TTL 0
    #   LabelStack.new(entries: [{ label: 16005, exp: 0, bottom: false, ttl: 64 }, ...])
    #   LabelStack.new(octets)              an ISIS::Octets
    #   LabelStack.new(other)               reads other's encoding back
    #
    # Building never validates: S may be set on any entry or none, and Exp
    # and TTL hold any value they fit. Only what cannot be represented is
    # refused: a label past 20 bits, an Exp past 3, a TTL past 8.
    #
    # Parsing consumes the entries up to and including the first with S
    # set, and leaves the rest, which is the packet the stack carries.
    # With no S, it takes whole entries while four octets remain; fewer is
    # a stack cut short, kept as +tail+ and written back.
    #
    # Used by the netlink adapter for the labels a route pushes, and by
    # TI-LFA's repair stacks (routescope docs/design/ti-lfa.md).
    class LabelStack
      include Node

      # One entry. +bottom+ is the S bit.
      Entry = Struct.new(:label, :exp, :bottom, :ttl) do
        def to_hash
          { label: label, exp: exp, bottom: bottom, ttl: ttl }
        end

        def word
          (label << 12) | (exp << 9) | (bottom ? 0x100 : 0) | ttl
        end
      end

      LABEL_MAX = 0xfffff

      attr_reader :entries, :tail

      def labels
        @entries.map(&:label)
      end

      def encode
        (@entries.map { [_1.word].pack("N") }.join + @tail).b
      end

      def to_hash
        h = { entries: @entries.map(&:to_hash) }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h
      end

      # tcpdump's form: "(label 16005, exp 0, ttl 64) (label 16007, exp 0,
      # [S], ttl 64)".
      def to_s
        parts = @entries.map do |e|
          "(label #{e.label}, exp #{e.exp}, #{'[S], ' if e.bottom}ttl #{e.ttl})"
        end
        parts << "(#{@tail.bytesize} octets cut short)" unless @tail.empty?
        parts.join(" ")
      end

      def inspect
        "#<ISIS::Mpls::LabelStack #{self}>"
      end

      private

      def parse(octets)
        @entries = []
        @tail = "".b
        while octets.bytesize >= 4
          word = octets.slice!(0, 4).unpack1("N")
          entry = Entry.new(word >> 12, (word >> 9) & 0x7, word.anybits?(0x100), word & 0xff)
          @entries << entry
          return if entry.bottom
        end
        @tail = octets.slice!(0, octets.bytesize).b
      end

      def from_fields(*labels, entries: nil, exp: 0, ttl: 0, tail: "")
        flat = labels.flatten
        list = entries || flat.each_with_index.map do |label, i|
          { label: label, exp: exp, bottom: i == flat.size - 1, ttl: ttl }
        end
        @entries = list.map { entry(_1) }
        @tail = tail.b
      end

      def from_hash(hash)
        from_fields(entries: hash.fetch(:entries), tail: [hash.fetch(:tail, "")].pack("H*"))
      end

      def entry(h)
        label = Integer(h.fetch(:label))
        exp = Integer(h.fetch(:exp, 0))
        ttl = Integer(h.fetch(:ttl, 0))
        raise ArgumentError, "label #{label} does not fit in 20 bits" unless (0..LABEL_MAX).cover?(label)
        raise ArgumentError, "Exp #{exp} does not fit in 3 bits" unless (0..7).cover?(exp)
        raise ArgumentError, "TTL #{ttl} does not fit in 8 bits" unless (0..255).cover?(ttl)

        Entry.new(label, exp, h.fetch(:bottom, false) ? true : false, ttl)
      end
    end
  end
end
