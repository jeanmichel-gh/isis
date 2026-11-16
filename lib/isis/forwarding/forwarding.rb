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
    # +labels+ maps [circuit, neighbor] to the label each next hop pushes
    # (segment routing), or is nil.
    Operation = Struct.new(:kind, :route, :level, :labels, keyword_init: true) do
      def to_s
        "#{kind} #{kind == :withdraw ? route.prefix : route}"
      end
    end

    # One label route operation: +kind+ :install or :withdraw, +entry+ the
    # Spf::Labels::Entry.
    LabelOperation = Struct.new(:kind, :entry, keyword_init: true) do
      def to_s
        hops = entry.hops.map { |a, out| "#{out == 3 ? 'pop' : out} via #{a.circuit}" }.join(", ")
        "#{kind} label #{entry.label} #{entry.op}#{hops.empty? ? '' : " #{hops}"}"
      end
    end

    # The operations that take +before+ to +after+, two Decision Process
    # route tables keyed by prefix. A route this system advertises itself
    # has no next hop and is not a forwarding entry, so it counts as
    # absent: local to remote is an install, remote to local a withdrawal.
    #
    # +labels+ is [before, after], each a prefix => { [circuit, neighbor]
    # => label } map or nil: a route whose pushed labels change is replaced.
    def self.operations(before, after, level: nil, labels: [nil, nil])
      was, now = labels.map { |l| l || {} }
      (before.keys | after.keys).sort.filter_map do |prefix|
        old = before[prefix]
        new = after[prefix]
        old = nil if old&.local?
        new = nil if new&.local?
        if old.nil? && new.nil? then nil
        elsif old.nil? then Operation.new(kind: :install, route: new, level: level, labels: now[prefix])
        elsif new.nil? then Operation.new(kind: :withdraw, route: old, level: level)
        elsif old.metric != new.metric || old.adjacencies != new.adjacencies || was[prefix] != now[prefix]
          Operation.new(kind: :replace, route: new, level: level, labels: now[prefix])
        end
      end
    end

    # The label routes of every level, installed through one adapter.
    # Label routes have no metric to order two levels by, so where both
    # levels give a label, Level 1's is installed: the same order as IP
    # routes, RFC 1142 7.2.12. (docs/design/sr-mpls.md, open question 3.)
    # The whole table is compared each time and only what changed is sent.
    class LabelTable
      attr_reader :installed

      def initialize(adapter:, log:)
        @adapter = adapter
        @log = log
        @tables = {}
        @installed = {}
        @adapter.flush_labels if @adapter.respond_to?(:flush_labels)
      end

      # +labels+ is the level's Spf::Labels, or nil for none.
      def update(level, labels)
        @tables[level] = labels ? labels.entries : {}
        want = {}
        @tables.keys.sort.reverse_each { |l| want.merge!(@tables[l]) }
        (@installed.keys - want.keys).sort.each do |label|
          @adapter.apply(LabelOperation.new(kind: :withdraw, entry: @installed.delete(label)))
        end
        want.keys.sort.each do |label|
          next if @installed[label] == want[label]

          @installed[label] = want[label] if @adapter.apply(LabelOperation.new(kind: :install, entry: want[label]))
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
