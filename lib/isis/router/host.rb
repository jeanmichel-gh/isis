# frozen_string_literal: true

require "ipaddr"

module ISIS
  class Router
    # The Linux host a Router runs on: a raw socket per interface through
    # datalink-socket, its MAC from sysfs, its IPv6 link-local addresses
    # from /proc/net/if_inet6, and netlink for routes. Opening a raw
    # socket needs root or CAP_NET_RAW.
    class Host
      def initialize(log:, sysfs: "/sys/class/net", if_inet6: "/proc/net/if_inet6", proc_mpls: "/proc/sys/net/mpls")
        @log = log
        @proc_mpls = proc_mpls
        @sysfs = sysfs
        @if_inet6 = if_inet6
        @sockets = []
        @source = nil
      end

      def link(name)
        socket = Datalink::Socket.new(name, recv_timeout: 0.01).open
        @sockets << socket
        { transport: Link::SocketTransport.new(socket), snpa: mac(name), link_local: link_local(name) }
      end

      # Level 1 at priority 21 and Level 2 at 22, so a prefix both reach
      # goes by Level 1 (RFC 1142 7.2.12).
      def forwarding(level, interfaces: {})
        Forwarding::Netlink.new(log: @log, priority: 20 + level, interfaces: interfaces)
      end

      # Make the host take label routes for +interfaces+: MPLS input on each
      # (net.mpls.conf.IF.input), and a check that net.mpls.platform_labels
      # reaches +highest+. Returns nil when it can, else why not. The
      # mpls_router module and the platform label table are the host's to
      # set: a container cannot load a module, and the size is a choice.
      def mpls(interfaces, highest:)
        table = File.join(@proc_mpls, "platform_labels")
        return "#{table} is missing: is the mpls_router module loaded?" unless File.exist?(table)

        size = Integer(File.read(table).strip)
        return "net.mpls.platform_labels is #{size}, and labels go up to #{highest}" if size <= highest

        interfaces.each do |name|
          path = File.join(@proc_mpls, "conf", name, "input")
          File.write(path, "1\n") if File.exist?(path)
        end
        nil
      rescue SystemCallError => e
        "the MPLS settings cannot be written: #{e.message}"
      end

      def route_source
        @source ||= Forwarding::Netlink.new(log: @log)
      end

      def close
        @sockets.each(&:close)
        @sockets.clear
        @source&.close
        @source = nil
      end

      def mac(name) = File.read(File.join(@sysfs, name, "address")).strip

      # The interface's link-local addresses: scope 0x20 in if_inet6.
      def link_local(name)
        return [] unless File.exist?(@if_inet6)

        File.foreach(@if_inet6).filter_map do |line|
          hex, _, _, scope, _, dev = line.split
          IPAddr.new_ntoh([hex].pack("H*")).to_s if dev == name && scope == "20"
        end
      end
    end
  end
end
