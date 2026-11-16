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
      # MPLS, from linux/rtnetlink.h, lwtunnel.h and mpls_iptunnel.h (printed
      # by a C program on the lab VM, kernel 7.0, 2026-11-16).
      RTA_VIA = 18
      RTA_NEWDST = 19
      RTA_ENCAP_TYPE = 21
      RTA_ENCAP = 22
      NLA_F_NESTED = 0x8000
      LWTUNNEL_ENCAP_MPLS = 1
      MPLS_IPTUNNEL_DST = 1
      AF_MPLS = 28
      # RFC 3032 section 2.1: "A value of 3 represents the Implicit NULL
      # Label", a label never sent: the stack is popped instead.
      IMPLICIT_NULL = 3

      RTPROT_KERNEL = 2
      RTPROT_BOOT = 3
      RTPROT_STATIC = 4
      RTPROT_ISIS = 187
      RT_TABLE_MAIN = 254
      RT_SCOPE_UNIVERSE = 0
      RT_SCOPE_LINK = 253
      RT_SCOPE_NOWHERE = 255
      RTN_UNICAST = 1

      FAMILIES = { ipv4: Socket::AF_INET, ipv6: Socket::AF_INET6, mpls: AF_MPLS }.freeze

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
        return apply_label(operation) if operation.is_a?(LabelOperation)

        route = operation.route
        message =
          if operation.kind == :withdraw
            delete_message(route.family, route.prefix)
          else
            hops = next_hops(route, operation.labels || {})
            if hops.empty?
              @log.warn("route #{route} not installed: no next hop has an #{route.family} address")
              return false
            end
            new_message(route.family, route.prefix, hops)
          end
        @log.debug("netlink #{operation}, priority #{@priority}")
        request(message, operation.to_s)
      end

      # One label route in or out (segment routing, Spf::Labels). Its next
      # hops go by their IPv4 address, else their IPv6 one; a label with no
      # next hop pops and looks the packet up again, through lo. A pop
      # toward a next hop is a label route with no new label.
      def apply_label(operation)
        entry = operation.entry
        message =
          if operation.kind == :withdraw
            label_delete_message(entry.label)
          else
            hops = entry.hops.filter_map do |a, out|
              via = a.address ? [:ipv4, a.address] : (a.address6 && [:ipv6, a.address6])
              [ifindex(@interfaces.fetch(a.circuit, a.circuit)), *via, out == IMPLICIT_NULL ? nil : out] if via
            end
            hops = [[ifindex("lo"), nil, nil, nil]] if entry.hops.empty?
            if hops.empty?
              @log.warn("label #{entry.label} not installed: no next hop has an address")
              return false
            end
            label_message(entry.label, hops)
          end
        @log.debug("netlink #{operation}")
        request(message, operation.to_s)
      end

      # Remove every route of this adapter's protocol, table and priority,
      # as a start with no stale entries from an earlier run needs.
      # Returns how many it removed. Label routes are flush_labels's.
      def flush
        mine = dump.select do |r|
          r[:family] != :mpls && r[:protocol] == @protocol && r[:table] == @table && r[:priority] == @priority
        end
        mine.count do |r|
          request(delete_message(r[:family], r[:prefix]), "flush #{r[:prefix]}")
        end
      end

      # Remove every label route of this adapter's protocol. Returns how
      # many it removed.
      def flush_labels
        dump.select { |r| r[:family] == :mpls && r[:protocol] == @protocol }.count do |r|
          request(label_delete_message(r[:label]), "flush label #{r[:label]}")
        end
      end

      # Every IPv4 and IPv6 route in the kernel, as { family:, prefix:,
      # table:, protocol:, scope:, type:, priority: }, for Redistribution
      # to choose from. Label routes are left out.
      def routes
        dump.reject { |r| r[:family] == :mpls }
      end

      def close
        @socket&.close
        @socket = nil
      end

      # Messages, packed without a socket so a test can read them.

      # RTM_NEWROUTE for +prefix+ through +hops+, [ifindex, gateway] each,
      # or [ifindex, gateway, label] to push a label on the way out:
      # RTA_ENCAP_TYPE LWTUNNEL_ENCAP_MPLS and a nested RTA_ENCAP holding
      # MPLS_IPTUNNEL_DST, as `ip route add ... encap mpls LABEL` sends it.
      # In a multipath route each next hop carries its own.
      def new_message(family, prefix, hops)
        addr, len = split(prefix)
        attrs = attr(RTA_TABLE, [@table].pack("L")) + attr(RTA_DST, addr.hton) +
                attr(RTA_PRIORITY, [@priority].pack("L"))
        if hops.size == 1
          ifindex, gateway, label = hops.first
          attrs += attr(RTA_OIF, [ifindex].pack("l")) + attr(RTA_GATEWAY, IPAddr.new(gateway).hton) + encap(label)
        else
          attrs += attr(RTA_MULTIPATH, hops.map { |i, g, l| nexthop(i, g, l) }.join)
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

      # RTM_NEWROUTE for an MPLS label: rtmsg AF_MPLS with a 20 bit
      # destination, RTA_DST the label, then for each next hop [ifindex,
      # family, address, out-label]: RTA_NEWDST the label it leaves with,
      # none for a pop; RTA_VIA the family as a u16 and the address; and
      # the interface. A next hop with no address pops and looks up again,
      # RTA_OIF alone. The layout is iproute2 6.19's for `ip -M route add
      # L as M via inet A dev D proto 187`, captured with strace in a
      # network namespace: no RTA_TABLE and no RTA_PRIORITY.
      def label_message(label, hops)
        attrs = attr(RTA_DST, stack(label))
        if hops.size == 1
          attrs += label_hop(*hops.first)
        else
          attrs += attr(RTA_MULTIPATH, hops.map do |ifindex, family, address, out|
            body = label_hop(nil, family, address, out)
            [8 + body.bytesize, 0, 0, ifindex].pack("SCCl").b + body
          end.join)
        end
        header(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
               rtmsg(:mpls, 20, RT_SCOPE_UNIVERSE, RTN_UNICAST) + attrs)
      end

      # RTM_DELROUTE for an MPLS label, as `ip -M route del L proto 187`.
      def label_delete_message(label)
        header(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK,
               rtmsg(:mpls, 20, RT_SCOPE_UNIVERSE, RTN_UNICAST) + attr(RTA_DST, stack(label)))
      end

      def dump_message
        header(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, rtmsg(:any, 0, 0, 0))
      end

      private

      # [ifindex, gateway, label] for each adjacency with an address in the
      # route's family, in the route's order. +labels+ maps [circuit,
      # neighbor] to the label to push, implicit null pushing none.
      def next_hops(route, labels = {})
        route.adjacencies.filter_map do |a|
          gateway = a.next_hop(route.family)
          next unless gateway

          label = labels[[a.circuit, a.neighbor.b]]
          [ifindex(@interfaces.fetch(a.circuit, a.circuit)), gateway, label == IMPLICIT_NULL ? nil : label]
        end.uniq
      end

      # One label stack entry, RFC 3032 section 2.1: the label in the top
      # 20 bits, then TC, the bottom-of-stack bit (0x100, one label here),
      # and a TTL of 0, which the kernel fills in. Network order.
      def stack(label)
        [(label << 12) | 0x100].pack("N")
      end

      # The push of +label+, or nothing.
      def encap(label)
        return "".b if label.nil?

        attr(RTA_ENCAP | NLA_F_NESTED, attr(MPLS_IPTUNNEL_DST, stack(label))) +
          attr(RTA_ENCAP_TYPE, [LWTUNNEL_ENCAP_MPLS].pack("S"))
      end

      def label_hop(ifindex, family, address, out)
        a = out.nil? ? "".b : attr(RTA_NEWDST, stack(out))
        a += attr(RTA_VIA, [FAMILIES.fetch(family)].pack("S") + IPAddr.new(address).hton) if family
        a += attr(RTA_OIF, [ifindex].pack("l")) if ifindex
        a
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

      def nexthop(ifindex, gateway, label = nil)
        gw = attr(RTA_GATEWAY, IPAddr.new(gateway).hton) + encap(label)
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
        family, dst_len, _, _, table, protocol, scope, type = body.unpack("C8")
        attrs = {}
        rest = body.byteslice(12..)
        while rest.bytesize >= 4
          len, kind = rest.unpack("SS")
          break if len < 4

          attrs[kind] = rest.byteslice(4, len - 4)
          rest = rest.byteslice((len + 3) & ~3..) || "".b
        end
        table = attrs[RTA_TABLE].unpack1("L") if attrs[RTA_TABLE]
        if family == AF_MPLS
          return { family: :mpls, label: attrs[RTA_DST] && (attrs[RTA_DST].unpack1("N") >> 12), table: table,
                   protocol: protocol, scope: scope, type: type, priority: nil }
        end
        fam = family == Socket::AF_INET6 ? :ipv6 : :ipv4
        dst = attrs[RTA_DST] || ("\0".b * (fam == :ipv6 ? 16 : 4))
        { family: fam, prefix: "#{IPAddr.new_ntoh(dst)}/#{dst_len}", table: table, protocol: protocol,
          scope: scope, type: type, priority: attrs[RTA_PRIORITY]&.unpack1("L") }
      end
    end
  end
end
