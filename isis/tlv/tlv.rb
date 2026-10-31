# frozen_string_literal: true

module ISIS
  # IS-IS TLVs: a type octet, a length octet, then that many value bytes.
  module Tlv
    MAX_VALUE = 255

    # entries: an array of [type, value_bytes]. Returns the packed bytes.
    def self.encode(entries)
      entries.map do |type, value|
        v = value.b
        raise Error, "TLV #{type} value too long (#{v.bytesize} > #{MAX_VALUE})" if v.bytesize > MAX_VALUE

        [type, v.bytesize].pack("C2") + v
      end.join
    end

    # Returns an array of [type, value_bytes]. Stops at a truncated tail.
    def self.parse(bytes)
      b = bytes.b
      out = []
      i = 0
      while i + 2 <= b.bytesize
        type = b.getbyte(i)
        len  = b.getbyte(i + 1)
        value = b[i + 2, len] || ""
        break if value.bytesize < len

        out << [type, value]
        i += 2 + len
      end
      out
    end
  end
end
