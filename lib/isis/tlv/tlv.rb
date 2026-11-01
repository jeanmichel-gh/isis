# frozen_string_literal: true

module ISIS
  # A TLV: one type octet, one length octet, then that many octets of
  # value. Every TLV in IS-IS has this framing, known type or not, which is
  # why an unknown TLV can still be framed, kept and replayed.
  #
  # A subclass knows its value and nothing else. It hands the value to
  # Tlv#encode, and this class writes the type and the length. This is the
  # only place in the library that knows how a TLV is framed.
  class Tlv
    include Node

    MAX_VALUE = 255
    HEADER = 2

    # type number => class, and hash key => class, for the factory and for
    # TlvList#from_hash. Unregistered types become Tlv::Unknown.
    @by_type = {}
    @by_key = {}

    class << self
      attr_reader :by_type, :by_key

      def register(type, key, klass)
        @by_type[type] = klass
        @by_key[key] = klass
        klass
      end

      # The class for a type number: a registered one, else Unknown.
      def class_for(type)
        @by_type.fetch(type, Unknown)
      end

      # Read one TLV off the front of +octets+, consuming exactly its
      # octets, within +boundary+ octets of the start (default: all of
      # them). Returns nil, consuming nothing, if fewer than two octets are
      # inside the boundary, since that cannot be a TLV.
      #
      # A declared length that runs past the boundary is clamped to it and
      # never followed. The TLV keeps the declared length and replays it.
      def factory(octets, boundary: octets.bytesize)
        boundary = [boundary, octets.bytesize].min
        return nil if boundary < HEADER

        declared = octets.getbyte(1)
        take = [declared, boundary - HEADER].min
        raw = Octets.new(octets.byteslice(0, HEADER + take))
        octets.replace(octets.byteslice(HEADER + take..) || "")
        class_for(octets_type(raw)).new(raw)
      end

      private

      def octets_type(raw)
        raw.getbyte(0)
      end
    end

    # Frame +value+ as this TLV. Refuses only a value it cannot frame: a
    # length over 255 cannot be written in one octet, and writing it
    # truncated would put a different TLV on the wire than was asked for.
    # Splitting an oversized value is a builder's job, not this one's.
    def encode(value, length: nil)
      n = value.bytesize
      raise ArgumentError, "TLV #{type} value is #{n} octets, max #{MAX_VALUE}" if n > MAX_VALUE

      out = ISIS.buffer
      out << [type, length || n].pack("CC") << value.b
      out
    end

    # A TLV whose type isis4r does not implement. It keeps its value whole,
    # and if its declared length ran past the end of what arrived, it keeps
    # that declared length too, so it replays exactly what it was given.
    class Unknown < Tlv
      attr_reader :type, :value, :declared_length

      def self.hash_key
        :unknown
      end

      # Replays a clamped length as declared, so a malformed capture goes
      # back out malformed.
      def encode
        super(@value, length: @declared_length)
      end

      # True when the declared length ran past the octets that arrived.
      def clamped?
        !@declared_length.nil?
      end

      def to_hash
        { type: @type, value: @value.unpack1("H*") }
      end

      def to_s
        note = clamped? ? ", declared #{@declared_length}" : ""
        "TLV #{@type}, #{@value.bytesize} octets#{note}"
      end

      private

      def parse(octets)
        raise ArgumentError, "a TLV needs at least #{HEADER} octets" if octets.bytesize < HEADER

        @type = octets.getbyte(0)
        declared = octets.getbyte(1)
        @value = octets.byteslice(HEADER, declared).b
        @declared_length = declared unless @value.bytesize == declared
        octets.replace(octets.byteslice(HEADER + @value.bytesize..) || "")
      end

      def from_fields(type, value)
        type = Integer(type)
        raise ArgumentError, "TLV type #{type} does not fit in one octet" unless (0..255).cover?(type)

        @type = type
        @value = value.b
        @declared_length = nil
      end

      def from_hash(hash)
        from_fields(hash.fetch(:type), [hash.fetch(:value)].pack("H*"))
      end
    end

    # An ordered list of TLVs, as a PDU body carries them. Order is kept and
    # repetition is ordinary: many TLVs of one type is the design of IS-IS,
    # not an exception, so this is a list and never a map by type.
    #
    # Parsing follows the policy in CLAUDE.md: the boundary always wins, a
    # clamp is kept by the TLV that had it, every TLV read makes progress,
    # and octets that cannot be a TLV are kept as a tail.
    class List
      include Node
      include Enumerable

      attr_reader :tlvs, :tail

      # Read TLVs from the front of +octets+ until +boundary+ octets have
      # been consumed (default: all of them). Consumes exactly that much.
      def self.parse(octets, boundary: octets.bytesize)
        list = allocate
        list.send(:parse_bounded, octets, [boundary, octets.bytesize].min)
        list
      end

      def each(&block)
        @tlvs.each(&block)
      end

      def size
        @tlvs.size
      end

      def <<(tlv)
        @tlvs << tlv
        self
      end

      def encode
        out = ISIS.buffer
        @tlvs.each { |t| out << t.encode }
        out << @tail
        out
      end

      def to_hash
        h = { tlvs: @tlvs.map { |t| { t.class.hash_key => t.to_hash } } }
        h[:tail] = @tail.unpack1("H*") unless @tail.empty?
        h
      end

      def to_s
        lines = @tlvs.map(&:to_s)
        lines << "tail, #{@tail.bytesize} octets" unless @tail.empty?
        lines.join("\n")
      end

      private

      def parse(octets)
        parse_bounded(octets, octets.bytesize)
      end

      def parse_bounded(octets, boundary)
        @tlvs = []
        @tail = "".b
        remaining = boundary
        while remaining.positive?
          before = octets.bytesize
          tlv = Tlv.factory(octets, boundary: remaining)
          consumed = before - octets.bytesize
          # Fewer than two octets left, or a factory that took nothing: what
          # is left inside the boundary is a tail, never a loop.
          if tlv.nil? || consumed.zero?
            @tail = octets.byteslice(0, remaining).b
            octets.replace(octets.byteslice(remaining..) || "")
            break
          end
          @tlvs << tlv
          remaining -= consumed
        end
      end

      def from_fields(*tlvs)
        tlvs = tlvs.first if tlvs.size == 1 && tlvs.first.is_a?(Array)
        @tlvs = tlvs.dup
        @tail = "".b
      end

      def from_hash(hash)
        @tlvs = hash.fetch(:tlvs, []).map do |entry|
          key, value = entry.first
          klass = key == :unknown ? Unknown : Tlv.by_key.fetch(key)
          klass.new(value)
        end
        @tail = [hash.fetch(:tail, "")].pack("H*")
      end
    end
  end
end
