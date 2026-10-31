# frozen_string_literal: true

module ISIS
  # Getting IS-IS PDUs on and off an IEEE 802.3 link: the LLC header IS-IS
  # puts in front of its PDUs, and the multicast addresses it sends to.
  #
  # datalink-socket parses LLC generically. Deciding that a given SAP means
  # IS-IS is the protocol's job, which is why the check lives here.
  module Link
    # Well-known destination MACs for IS-IS on a LAN.
    ALL_L1_ISS = "01:80:c2:00:00:14"
    ALL_L2_ISS = "01:80:c2:00:00:15"

    module_function

    # The LLC header for IS-IS: DSAP and SSAP both the IS-IS SAP, UI control.
    def llc
      @llc ||= Datalink::LLC.new(dsap: Datalink::LLC::SAP_ISIS,
                                 ssap: Datalink::LLC::SAP_ISIS)
    end

    # True if a frame's SDU begins with the IS-IS LLC SAPs.
    def isis_llc?(sdu)
      sdu.bytesize >= Datalink::LLC::SIZE &&
        sdu.getbyte(0) == Datalink::LLC::SAP_ISIS &&
        sdu.getbyte(1) == Datalink::LLC::SAP_ISIS
    end

    # The AllL1ISs or AllL2ISs multicast MAC for a level.
    def all_iss(level)
      Datalink::MAC.new(level == 2 ? ALL_L2_ISS : ALL_L1_ISS)
    end
  end

  # Kept so existing callers of ISIS::ALL_L1_ISS keep working.
  ALL_L1_ISS = Link::ALL_L1_ISS
  ALL_L2_ISS = Link::ALL_L2_ISS
end
