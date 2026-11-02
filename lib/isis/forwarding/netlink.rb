# frozen_string_literal: true

require "socket"
require "ipaddr"

module ISIS
  module Forwarding
    # Linux forwarding adapter: rtnetlink over an AF_NETLINK socket, with
    # the messages packed in Ruby (no native extension, no `ip` binary).
    # Needs root or CAP_NET_ADMIN in the network namespace it runs in.
    #
    # The layouts are linux/netlink.h and linux/rtnetlink.h, in host byte
    # order as netlink is:
    #
    #   nlmsghdr   u32 length, u16 type, u16 flags, u32 sequence, u32 port
    #   rtmsg      u8 family, dst_len, src_len, tos, table, protocol,
    #              scope, type, then u32 flags
    #   rtattr     u16 length, u16 type, value, padded to four octets
    #   rtnexthop  u16 length, u8 flags, u8 hops, s32 ifindex, then
    #              its own attributes, inside RTA_MULTIPATH
    #
    # A route goes in as RTM_NEWROUTE with NLM_F_CREATE | NLM_F_REPLACE, so
    # install and replace are the same message, with protocol RTPROT_ISIS
    # so `ip route show proto isis` lists exactly what this adapter put
    # there. One next hop is RTA_OIF and RTA_GATEWAY; several are
    # RTA_MULTIPATH. A withdrawal is RTM_DELROUTE naming the prefix, table,
    # protocol and priority, which removes every next hop.
    #
    # +priority+ is the kernel's route metric. Give each level its own, the
    # Level 1 one lower: then a prefix both levels reach is in the kernel
    # twice and the kernel uses the Level 1 route. That is RFC 1142
    # 7.2.12's order: a destination in the area "will be reached
    # exclusively by use of level 1 routeing". Neither withdrawal touches
    # the other's.
    #
    # Logging: each operation at debug, and a refusal from the kernel at
    # warn with its errno. A refused operation returns false; nothing
    # raises, so a route the kernel will not take does not stop the router.
    class Netlink
      NLMSG_ERROR = 2
      NLMSG_DONE = 3
      RTM_NEWROUTE = 24
      RTM_DELROUTE = 25
      RTM_GETROUTE = 26

      NLM_F_REQUEST = 0x001
      NLM_F_ACK = 0x004
      NLM_F_REPLACE = 0x100
      NLM_F_CREATE = 0x400
      NLM_F_DUMP = 0x300

      RTA_DST = 1
      RTA_OIF = 4
      RTA_GATEWAY = 5
      RTA_PRIORITY = 6
      RTA_MULTIPATH = 9
      RTA_TABLE = 15

      RTPROT_ISIS = 187
      RT_TABLE_MAIN = 254
      RT_SCOPE_UNIVERSE = 0
      RT_SCOPE_NOWHERE = 255
      RTN_UNICAST = 1

      FAMILIES = { ipv4: Socket::AF_INET, ipv6: Socket::AF_INET6 }.freeze

      attr_reader :table, :protocol, :priority, :errors

      # +interfaces+ maps a circuit name to its interface where the two
      # differ; otherwise the circuit's name is its interface. +socket+ is
      # for a test; by default one is opened on first use.
      def initialize(log:, priority: 20, table: RT_TABLE_MAIN, protocol: RTPROT_ISIS, interfaces: {}, socket: nil)
        @log = log
        @priority = priority
        @table = table
        @protocol = protocol
        @interfaces = interfaces
        @socket = socket
        @sequence = 0
        @errors = 0
      end

      def apply(operation)
        route = operation.route
        message =
          if operation.kind == :withdraw
            delete_message(route.family, route.prefix)
          else
            hops = next_hops(route)
            if hops.empty?
              @log.warn("route #{route} not installed: no next hop has an #{route.family} address")
              return false
            end
            new_message(route.family, route.prefix, hops)
          end
        @log.debug("netlink #{operation}, priority #{@priority}")
        request(message, operation.to_s)
      end

      # Remove every route of this adapter's protocol, table and priority,
      # as a start with no stale entries from an earlier run needs.
      # Returns how many it removed.
      def flush
        mine = dump.select do |r|
          r[:protocol] == @protocol && r[:table] == @table && r[:priority] == @priority
        end
        mine.count do |r|
          request(delete_message(r[:family], r[:prefix]), "flush #{r[:prefix]}")
        end
      end

      def close
        @socket&.close
        @socket = nil
      end

      # Messages, packed without a socket so a test can read them.

      # RTM_NEWROUTE for +prefix+ through +hops+, [ifindex, gateway] each.
      def new_message(family, prefix, hops)
        addr, len = split(prefix)
        attrs = attr(RTA_TABLE, [@table].pack("L")) + attr(RTA_DST, addr.hton) +
                attr(RTA_PRIORITY, [@priority].pack("L"))
        if hops.size == 1
          ifindex, gateway = hops.first
          attrs += attr(RTA_OIF, [ifindex].pack("l")) + attr(RTA_GATEWAY, IPAddr.new(gateway).hton)
        else
          attrs += attr(RTA_MULTIPATH, hops.map { |i, g| nexthop(i, g) }.join)
        end
        header(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
               rtmsg(family, len, RT_SCOPE_UNIVERSE, RTN_UNICAST) + attrs)
      end

      # RTM_DELROUTE for +prefix+. Scope RT_SCOPE_NOWHERE and type zero
      # match any, as `ip route del` sends.
      def delete_message(family, prefix)
        addr, len = split(prefix)
        attrs = attr(RTA_TABLE, [@table].pack("L")) + attr(RTA_DST, addr.hton) +
                attr(RTA_PRIORITY, [@priority].pack("L"))
        header(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, rtmsg(family, len, RT_SCOPE_NOWHERE, 0) + attrs)
      end

      def dump_message
        header(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, rtmsg(:any, 0, 0, 0))
      end

      private

      # [ifindex, gateway] for each adjacency with an address in the
      # route's family, in the route's order.
      def next_hops(route)
        route.adjacencies.filter_map do |a|
          gateway = a.next_hop(route.family)
          [ifindex(@interfaces.fetch(a.circuit, a.circuit)), gateway] if gateway
        end.uniq
      end

      def ifindex(name)
        Integer(File.read("/sys/class/net/#{name}/ifindex"))
      end

      def split(prefix)
        addr = IPAddr.new(prefix)
        [addr, addr.prefix]
      end

      def header(type, flags, body)
        @sequence += 1
        [16 + body.bytesize, type, flags, @sequence, 0].pack("LSSLL").b + body
      end

      def rtmsg(family, dst_len, scope, type)
        f = family == :any ? 0 : FAMILIES.fetch(family)
        [f, dst_len, 0, 0, @table < 256 ? @table : 0, @protocol, scope, type, 0].pack("C8L").b
      end

      def attr(type, value)
        value = value.b
        a = [4 + value.bytesize, type].pack("SS").b + value
        a + ("\0".b * (-a.bytesize % 4))
      end

      def nexthop(ifindex, gateway)
        gw = attr(RTA_GATEWAY, IPAddr.new(gateway).hton)
        [8 + gw.bytesize, 0, 0, ifindex].pack("SCCl").b + gw
      end

      def socket
        @socket ||= Socket.new(Socket::AF_NETLINK, Socket::SOCK_RAW, 0).tap do |s|
          s.bind([Socket::AF_NETLINK, 0, 0, 0].pack("SSLL"))
        end
      end

      # Send +message+ and read the kernel's acknowledgement.
      def request(message, what)
        sequence = message.unpack1("@8L")
        socket.send(message, 0)
        loop do
          replies(socket.recv(65_536)) do |type, seq, body|
            next unless seq == sequence && type == NLMSG_ERROR

            code = body.unpack1("l")
            return true if code.zero?

            @errors += 1
            name = SystemCallError.new(nil, -code).class.name.sub("Errno::", "")
            @log.warn("netlink #{what} refused by the kernel: #{name} (#{-code})")
            return false
          end
        end
      end

      # The routes in the kernel, each as a hash.
      def dump
        message = dump_message
        sequence = message.unpack1("@8L")
        socket.send(message, 0)
        routes = []
        loop do
          replies(socket.recv(65_536)) do |type, seq, body|
            next unless seq == sequence
            return routes if type == NLMSG_DONE
            next unless type == RTM_NEWROUTE

            routes << parse_route(body)
          end
        end
      end

      def replies(data)
        until data.bytesize < 16
          len, type, _flags, seq = data.unpack("LSSL")
          break if len < 16

          yield type, seq, data.byteslice(16, len - 16)
          data = data.byteslice((len + 3) & ~3..) || "".b
        end
      end

      def parse_route(body)
        family, dst_len, _, _, table, protocol = body.unpack("C6")
        attrs = {}
        rest = body.byteslice(12..)
        while rest.bytesize >= 4
          len, type = rest.unpack("SS")
          break if len < 4

          attrs[type] = rest.byteslice(4, len - 4)
          rest = rest.byteslice((len + 3) & ~3..) || "".b
        end
        table = attrs[RTA_TABLE].unpack1("L") if attrs[RTA_TABLE]
        fam = family == Socket::AF_INET6 ? :ipv6 : :ipv4
        dst = attrs[RTA_DST] || ("\0".b * (fam == :ipv6 ? 16 : 4))
        { family: fam, prefix: "#{IPAddr.new_ntoh(dst)}/#{dst_len}", table: table, protocol: protocol,
          priority: attrs[RTA_PRIORITY]&.unpack1("L") }
      end
    end
  end
end
