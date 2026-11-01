# frozen_string_literal: true

module ISIS
  class Error < StandardError; end
  class ParseError < Error; end

  # Wire octets, marked as such.
  #
  # A binary String and a field value String are the same class in Ruby, so
  # a constructor cannot tell them apart by looking. Octets is the mark: a
  # String handed to a constructor as an Octets is parsed, and any other
  # String is a field value. Never guess from the content.
  #
  # bgp4r marks by adding #is_packed to every String. A gem should not
  # change String for everyone who loads it, and a frozen literal cannot
  # carry that mark anyway, so isis4r uses this subclass instead.
  class Octets < String
    # Octets from a hex string, ignoring whitespace: "01 04 03490001".
    def self.from_hex(hex)
      clean = hex.delete(" \t\n")
      raise ArgumentError, "not hex: #{hex.inspect}" unless clean.match?(/\A(\h\h)*\z/)

      new([clean].pack("H*"))
    end

    def initialize(str = "")
      super(str.b)
      force_encoding(Encoding::BINARY)
    end

    def to_shex
      unpack1("H*")
    end
  end

  # A new empty buffer that is binary from the moment it exists, so a
  # later << of an Integer appends one octet and never a codepoint.
  def self.buffer
    String.new(encoding: Encoding::BINARY)
  end

  # The constructor contract shared by every node of a PDU tree. See
  # docs/building-objects.md for the order and why it is fixed.
  #
  # A class that includes Node defines:
  #   parse(octets)       fill self from Octets, consuming exactly its own
  #   from_hash(hash)     fill self from what to_hash answered
  #   from_fields(...)    fill self from field values
  #   encode              its complete octets
  module Node
    # Wire octets may come with keywords. Those are parse-time inputs, facts
    # the octets do not carry themselves, and today there is one: id_width,
    # the System ID width the PDU's ID Length gave. A class that does not
    # need an input does not accept it.
    def initialize(*args, **fields)
      if args.size == 1
        arg = args.first
        return parse(arg, **fields) if arg.is_a?(Octets)

        if fields.empty?
          return parse(Octets.new(arg.encode), **arg.send(:parse_inputs)) if arg.instance_of?(self.class)
          return from_hash(arg) if arg.is_a?(Hash)
        end
      end
      from_fields(*args, **fields)
    end

    # The canonical form of a node: its encoding as a hex string.
    def to_shex
      encode.unpack1("H*")
    end

    private

    # The parse-time inputs a copy of this node needs to read its own
    # encoding back. None, unless a class says otherwise.
    def parse_inputs
      {}
    end
  end

  # An area address: a variable length string of octets, the area part of
  # an NSAP (RFC 1142 clause 9.2, encoded "according to the preferred binary
  # encoding specified in ISO 8348/Add.2").
  #
  # The presentation form is a convention copied from router output, with
  # no clause behind it: the first octet, then the rest in groups of two
  # octets, separated by dots, so three octets print as "49.0001". Parsing
  # ignores the dots, so "49.0001" and "490001" are the same area.
  class AreaAddress
    MAX = 255

    attr_reader :octets

    # From a presentation form, "49.0001", or another AreaAddress.
    def initialize(arg)
      @octets =
        case arg
        when AreaAddress then arg.octets
        when String then pton(arg)
        else raise ArgumentError, "cannot build an AreaAddress from #{arg.inspect}"
        end
      freeze
    end

    # From wire octets.
    def self.new_ntop(octets)
      allocate.tap { |a| a.send(:take, octets) }
    end

    def encode
      @octets.dup
    end

    def to_shex
      @octets.unpack1("H*")
    end

    def to_s
      hex = to_shex
      return hex if hex.length <= 2

      [hex[0, 2], *hex[2..].scan(/.{1,4}/)].join(".")
    end

    def inspect
      "#<ISIS::AreaAddress #{self}>"
    end

    private

    def take(octets)
      raise ArgumentError, "an area address is at most #{MAX} octets" if octets.bytesize > MAX

      @octets = octets.b.freeze
      freeze
    end

    def pton(text)
      hex = text.delete(".")
      raise ArgumentError, "bad area address #{text.inspect}" unless hex.match?(/\A(\h\h)*\z/)
      raise ArgumentError, "an area address is at most #{MAX} octets" if hex.length / 2 > MAX

      [hex].pack("H*").b.freeze
    end
  end

  # A 6-byte IS-IS system ID. Written as three dotted hex groups, for
  # example "1921.6800.1001". Immutable, compares by value.
  class SystemId
    LENGTH = 6

    attr_reader :bytes

    def initialize(arg)
      @bytes =
        case arg
        when SystemId then arg.bytes.dup
        when Array    then arg.map { |x| Integer(x) }
        when String   then parse(arg)
        else raise ArgumentError, "cannot build a SystemId from #{arg.inspect}"
        end
      unless @bytes.length == LENGTH && @bytes.all? { |b| (0..255).cover?(b) }
        raise ArgumentError, "system id must be 6 octets: #{arg.inspect}"
      end

      @bytes.freeze
      freeze
    end

    def self.from_bytes(str)
      b = str.b
      raise ArgumentError, "system id needs #{LENGTH} bytes" unless b.bytesize == LENGTH

      new(b.unpack("C#{LENGTH}"))
    end

    def encode
      @bytes.pack("C#{LENGTH}")
    end

    def to_s
      @bytes.each_slice(2).map { |hi, lo| format("%02x%02x", hi, lo) }.join(".")
    end

    def inspect
      "#<ISIS::SystemId #{self}>"
    end

    def ==(other)
      other.is_a?(SystemId) && other.bytes == @bytes
    end
    alias eql? ==

    def hash
      @bytes.hash
    end

    private

    def parse(str)
      hex = str.delete(".")
      raise ArgumentError, "bad system id #{str.inspect}" unless hex.match?(/\A\h{12}\z/)

      hex.scan(/../).map { |h| h.to_i(16) }
    end
  end
end
