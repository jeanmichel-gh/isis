# frozen_string_literal: true

module ISIS
  # The boundary between the protocol core and a forwarding table. The core
  # computes routes and hands an adapter route operations; it never touches
  # a kernel itself. An adapter answers +apply(operation)+ and returns true
  # when the operation took.
  #
  # Adapters are declared per platform, each stating its dependencies:
  #
  #   Forwarding::Recorder   none; keeps the operations, for tests
  #   Forwarding::Netlink    Linux; rtnetlink over an AF_NETLINK socket
  #                          from Ruby's Socket, with root or CAP_NET_ADMIN
  module Forwarding
    # One route operation. +kind+ is :install, :replace or :withdraw.
    # +route+ is the Spf::Route to install, or for a withdrawal the route
    # being withdrawn. +level+ is the level whose Decision Process asked.
    Operation = Struct.new(:kind, :route, :level, keyword_init: true) do
      def to_s
        "#{kind} #{kind == :withdraw ? route.prefix : route}"
      end
    end

    # The operations that take +before+ to +after+, two Decision Process
    # route tables keyed by prefix. A route this system advertises itself
    # has no next hop and is not a forwarding entry, so it counts as
    # absent: local to remote is an install, remote to local a withdrawal.
    def self.operations(before, after, level: nil)
      (before.keys | after.keys).sort.filter_map do |prefix|
        old = before[prefix]
        new = after[prefix]
        old = nil if old&.local?
        new = nil if new&.local?
        if old.nil? && new.nil? then nil
        elsif old.nil? then Operation.new(kind: :install, route: new, level: level)
        elsif new.nil? then Operation.new(kind: :withdraw, route: old, level: level)
        elsif old.metric != new.metric || old.adjacencies != new.adjacencies
          Operation.new(kind: :replace, route: new, level: level)
        end
      end
    end

    # An adapter that keeps what it was asked to do and installs nothing.
    class Recorder
      attr_reader :operations

      def initialize
        @operations = []
      end

      def apply(operation)
        @operations << operation
        true
      end
    end
  end
end
