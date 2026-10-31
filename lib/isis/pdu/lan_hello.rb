# frozen_string_literal: true

module ISIS
  # An IS-IS LAN Hello (IIH), level 1 or 2 (ISO 10589, clause 9.5).
  #
  # Wire layout, for ID length 6:
  #   Common header (8 bytes):
  #     IRPD(1)=0x83, length indicator(1)=27, version/PID ext(1)=1,
  #     ID length(1)=0, PDU type(1), version(1)=1, reserved(1)=0,
  #     max area addresses(1)=0
  #   LAN IIH header (19 bytes):
  #     circuit type(1), source ID(6), holding time(2), PDU length(2),
  #     priority(1), LAN ID(7)
  #   then TLVs.
  class LanHello
    HEADER_LEN = 27 # common(8) + LAN IIH(19), for a 6-byte system ID
    LAN_ID_LEN = 7  # DIS system ID(6) + pseudonode(1)

    attr_accessor :pdu_type, :circuit_type, :source_id, :holding_time,
                  :priority, :lan_id, :area_addresses, :neighbors, :protocols,
                  :max_area_addresses

    # area_addresses: dotted-hex strings like "49.0001" on input, stored as
    #   raw byte strings internally.
    # neighbors: MACs (the SNPAs of IS neighbors heard on this LAN).
    # protocols: NLPID integers.
    def initialize(source_id:, circuit_type: 1, holding_time: 30, priority: 64,
                   lan_id: nil, area_addresses: [], neighbors: [],
                   protocols: [NLPID_IPV4], pdu_type: L1_LAN_IIH,
                   max_area_addresses: 0)
      @source_id = coerce_sysid(source_id)
      @circuit_type = circuit_type
      @holding_time = holding_time
      @priority = priority
      @lan_id = lan_id || (@source_id.encode + "\x00".b) # default: self, pseudonode 0
      @area_addresses = area_addresses.map { |a| coerce_area(a) }
      @neighbors = neighbors.map { |n| coerce_mac(n) }
      @protocols = protocols
      @pdu_type = pdu_type
      @max_area_addresses = max_area_addresses
    end

    def encode
      tlvs = Tlv.encode(build_tlvs)
      pdu_length = HEADER_LEN + tlvs.bytesize

      common = [
        IRPD, HEADER_LEN, PROTOCOL_VERSION, 0,
        @pdu_type, PROTOCOL_VERSION, 0, @max_area_addresses
      ].pack("C8")

      iih = +""
      iih << [@circuit_type & 0x3].pack("C")
      iih << @source_id.encode
      iih << [@holding_time].pack("n")
      iih << [pdu_length].pack("n")
      iih << [@priority & 0x7f].pack("C")
      iih << lan_id_bytes

      common + iih + tlvs
    end

    def self.parse(bytes)
      b = bytes.b
      raise ParseError, "PDU shorter than header" if b.bytesize < HEADER_LEN

      irpd, _li, _vpe, _idlen, pdu_type, = b.unpack("C8")
      raise ParseError, format("not an IS-IS PDU (irpd=0x%02x)", irpd) unless irpd == IRPD

      circuit_type = b.getbyte(8) & 0x3
      source_id    = SystemId.from_bytes(b[9, 6])
      holding_time = b[15, 2].unpack1("n")
      pdu_length   = b[17, 2].unpack1("n")
      priority     = b.getbyte(19) & 0x7f
      lan_id       = b[20, LAN_ID_LEN]

      tlv_bytes = b[HEADER_LEN, [pdu_length - HEADER_LEN, 0].max] || b[HEADER_LEN..] || ""

      hello = new(source_id: source_id, circuit_type: circuit_type,
                  holding_time: holding_time, priority: priority,
                  pdu_type: pdu_type, area_addresses: [], neighbors: [],
                  protocols: [])
      hello.lan_id = lan_id

      Tlv.parse(tlv_bytes).each do |type, value|
        case type
        when TLV_AREA_ADDRESSES      then hello.area_addresses = parse_areas(value)
        when TLV_IS_NEIGHBORS        then hello.neighbors = parse_neighbors(value)
        when TLV_PROTOCOLS_SUPPORTED then hello.protocols = value.bytes
        end
      end
      hello
    end

    def level
      pdu_type == L2_LAN_IIH ? 2 : 1
    end

    def area_strings
      @area_addresses.map { |a| a.unpack1("H*") }
    end

    def to_s
      "IIH L#{level} from #{@source_id} hold=#{@holding_time} " \
        "areas=#{area_strings.join(',')} neighbors=[#{@neighbors.map(&:to_s).join(' ')}]"
    end

    def self.parse_areas(value)
      areas = []
      i = 0
      while i < value.bytesize
        len = value.getbyte(i)
        areas << (value[i + 1, len] || "")
        i += 1 + len
      end
      areas
    end

    def self.parse_neighbors(value)
      macs = []
      i = 0
      while i + 6 <= value.bytesize
        macs << Datalink::MAC.from_bytes(value[i, 6])
        i += 6
      end
      macs
    end

    private

    def build_tlvs
      entries = []
      unless @area_addresses.empty?
        entries << [TLV_AREA_ADDRESSES,
                    @area_addresses.map { |a| [a.bytesize].pack("C") + a }.join]
      end
      entries << [TLV_PROTOCOLS_SUPPORTED, @protocols.pack("C*")] unless @protocols.empty?
      entries << [TLV_IS_NEIGHBORS, @neighbors.map(&:encode).join] unless @neighbors.empty?
      entries
    end

    def lan_id_bytes
      b = @lan_id.b
      b + ("\x00" * (LAN_ID_LEN - b.bytesize))
    end

    def coerce_sysid(v)
      v.is_a?(SystemId) ? v : SystemId.new(v)
    end

    def coerce_mac(v)
      v.is_a?(Datalink::MAC) ? v : Datalink::MAC.new(v)
    end

    # "49.0001" -> "\x49\x00\x01". A raw byte string passes through.
    def coerce_area(v)
      return v.b if v.is_a?(String) && v.encoding == Encoding::ASCII_8BIT

      hex = v.to_s.delete(".")
      raise ArgumentError, "bad area address #{v.inspect}" unless hex.match?(/\A\h+\z/) && hex.length.even?

      [hex].pack("H*")
    end
  end
end
