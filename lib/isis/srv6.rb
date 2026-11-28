# frozen_string_literal: true

module ISIS
  # SRv6 as IS-IS carries it (RFC 9352). This file holds what the codec
  # and later the calculation share: the registry of endpoint behaviours.
  module Srv6
    # One endpoint behaviour: its codepoint, its registry name, the base
    # behaviour the name starts with, and the flavors after "with".
    Behavior = Struct.new(:number, :name, :base, :flavors) do
      def to_s = name
    end

    # The "SRv6 Endpoint Behaviors" registry: RFC 8986 section 10.2.2's
    # initial registrations, Table 6, then RFC 9800 section 12.1's, the
    # NEXT-CSID and REPLACE-CSID flavors. Both tables were read, and the
    # rows below are theirs, their names as the tables spell them. The
    # Reserved and Unassigned rows are left out, so their numbers are
    # unknown here, as is every number assigned elsewhere (RFC 9433, the
    # drafts). A SID keeps the number whatever it is; the name is only for
    # reading it (docs/design/srv6.md, "Wire format").
    #
    # RFC 8986 3.2: the behaviour cannot be inferred from the SID's
    # function bits, so a SID always carries its codepoint.
    BEHAVIORS = [
      [1, "End"],
      [2, "End with PSP"],
      [3, "End with USP"],
      [4, "End with PSP & USP"],
      [5, "End.X"],
      [6, "End.X with PSP"],
      [7, "End.X with USP"],
      [8, "End.X with PSP & USP"],
      [9, "End.T"],
      [10, "End.T with PSP"],
      [11, "End.T with USP"],
      [12, "End.T with PSP & USP"],
      [14, "End.B6.Encaps"],
      [15, "End.BM"],
      [16, "End.DX6"],
      [17, "End.DX4"],
      [18, "End.DT6"],
      [19, "End.DT4"],
      [20, "End.DT46"],
      [21, "End.DX2"],
      [22, "End.DX2V"],
      [23, "End.DT2U"],
      [24, "End.DT2M"],
      [27, "End.B6.Encaps.Red"],
      [28, "End with USD"],
      [29, "End with PSP & USD"],
      [30, "End with USP & USD"],
      [31, "End with PSP, USP & USD"],
      [32, "End.X with USD"],
      [33, "End.X with PSP & USD"],
      [34, "End.X with USP & USD"],
      [35, "End.X with PSP, USP & USD"],
      [36, "End.T with USD"],
      [37, "End.T with PSP & USD"],
      [38, "End.T with USP & USD"],
      [39, "End.T with PSP, USP & USD"],
      [32767, "The SID defined in RFC 8754"],
      [65535, "Opaque"],
      [43, "End with NEXT-CSID"],
      [44, "End with NEXT-CSID & PSP"],
      [45, "End with NEXT-CSID & USP"],
      [46, "End with NEXT-CSID, PSP & USP"],
      [47, "End with NEXT-CSID & USD"],
      [48, "End with NEXT-CSID, PSP & USD"],
      [49, "End with NEXT-CSID, USP & USD"],
      [50, "End with NEXT-CSID, PSP, USP & USD"],
      [52, "End.X with NEXT-CSID"],
      [53, "End.X with NEXT-CSID & PSP"],
      [54, "End.X with NEXT-CSID & USP"],
      [55, "End.X with NEXT-CSID, PSP & USP"],
      [56, "End.X with NEXT-CSID & USD"],
      [57, "End.X with NEXT-CSID, PSP & USD"],
      [58, "End.X with NEXT-CSID, USP & USD"],
      [59, "End.X with NEXT-CSID, PSP, USP & USD"],
      [85, "End.T with NEXT-CSID"],
      [86, "End.T with NEXT-CSID & PSP"],
      [87, "End.T with NEXT-CSID & USP"],
      [88, "End.T with NEXT-CSID, PSP & USP"],
      [89, "End.T with NEXT-CSID & USD"],
      [90, "End.T with NEXT-CSID, PSP & USD"],
      [91, "End.T with NEXT-CSID, USP & USD"],
      [92, "End.T with NEXT-CSID, PSP, USP & USD"],
      [93, "End.B6.Encaps with NEXT-CSID"],
      [94, "End.B6.Encaps.Red with NEXT-CSID"],
      [95, "End.BM with NEXT-CSID"],
      [96, "End.LBS with NEXT-CSID"],
      [97, "End.XLBS with NEXT-CSID"],
      [101, "End with REPLACE-CSID"],
      [102, "End with REPLACE-CSID & PSP"],
      [103, "End with REPLACE-CSID & USP"],
      [104, "End with REPLACE-CSID, PSP & USP"],
      [105, "End.X with REPLACE-CSID"],
      [106, "End.X with REPLACE-CSID & PSP"],
      [107, "End.X with REPLACE-CSID & USP"],
      [108, "End.X with REPLACE-CSID, PSP & USP"],
      [109, "End.T with REPLACE-CSID"],
      [110, "End.T with REPLACE-CSID & PSP"],
      [111, "End.T with REPLACE-CSID & USP"],
      [112, "End.T with REPLACE-CSID, PSP & USP"],
      [114, "End.B6.Encaps with REPLACE-CSID"],
      [115, "End.BM with REPLACE-CSID"],
      [116, "End.DX6 with REPLACE-CSID"],
      [117, "End.DX4 with REPLACE-CSID"],
      [118, "End.DT6 with REPLACE-CSID"],
      [119, "End.DT4 with REPLACE-CSID"],
      [120, "End.DT46 with REPLACE-CSID"],
      [121, "End.DX2 with REPLACE-CSID"],
      [122, "End.DX2V with REPLACE-CSID"],
      [123, "End.DT2U with REPLACE-CSID"],
      [124, "End.DT2M with REPLACE-CSID"],
      [127, "End.B6.Encaps.Red with REPLACE-CSID"],
      [128, "End with REPLACE-CSID & USD"],
      [129, "End with REPLACE-CSID, PSP & USD"],
      [130, "End with REPLACE-CSID, USP & USD"],
      [131, "End with REPLACE-CSID, PSP, USP & USD"],
      [132, "End.X with REPLACE-CSID & USD"],
      [133, "End.X with REPLACE-CSID, PSP & USD"],
      [134, "End.X with REPLACE-CSID, USP & USD"],
      [135, "End.X with REPLACE-CSID, PSP, USP & USD"],
      [136, "End.T with REPLACE-CSID & USD"],
      [137, "End.T with REPLACE-CSID, PSP & USD"],
      [138, "End.T with REPLACE-CSID, USP & USD"],
      [139, "End.T with REPLACE-CSID, PSP, USP & USD"],
      [140, "End.LBS with REPLACE-CSID"],
      [141, "End.XLBS with REPLACE-CSID"],
    ].to_h do |number, name|
      base, flavors = name.split(" with ", 2)
      [number, Behavior.new(number, name, base, flavors ? flavors.split(/, | & /) : []).freeze]
    end.freeze

    BY_NAME = BEHAVIORS.values.to_h { [_1.name, _1] }.freeze

    module_function

    # The behaviour of codepoint +number+, or nil when the registry here
    # does not have it.
    def behavior(number) = BEHAVIORS[number]

    # The name of +number+, or the number itself when unknown.
    def behavior_name(number) = BEHAVIORS[number]&.name || number

    # The codepoint for a name or a number. A number is taken as it is,
    # known or not; building never validates.
    def behavior_number(name_or_number)
      return Integer(name_or_number) if name_or_number.is_a?(Integer) || name_or_number.to_s.match?(/\A\d+\z/)

      b = BY_NAME[name_or_number.to_s] or
        raise ArgumentError, "no SRv6 behaviour #{name_or_number.inspect}; give a name from RFC 8986 or RFC 9800, or a number"
      b.number
    end
  end
end
