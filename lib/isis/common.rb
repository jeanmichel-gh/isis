# frozen_string_literal: true

module ISIS
  class Error < StandardError; end
  class ParseError < Error; end

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
