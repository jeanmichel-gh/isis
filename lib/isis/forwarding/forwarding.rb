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

    # One TI-LFA backup route (Spf::Backups): +kind+ :install, :replace or
    # :withdraw, the +prefix+ and its +family+, and for an install the
    # +adjacency+ it leaves on and the +labels+ it pushes, top first. An
    # adapter puts it beside the route, at a worse priority, so the kernel
    # takes it only when the route's next hop is gone (docs/ti-lfa.md).
    BackupOperation = Struct.new(:kind, :prefix, :family, :adjacency, :labels, :level, keyword_init: true) do
      def to_s
        return "withdraw backup #{prefix}" if kind == :withdraw

        "#{kind} backup #{prefix} via #{adjacency.circuit} push #{labels.empty? ? 'nothing' : labels.join('/')}"
      end
    end

    # The backup operations that take +before+ to +after+, each a prefix
    # => Spf::Backups result map or nil. Only a Backup is a route: ECMP and
    # unprotected have none.
    def self.backup_operations(before, after, level: nil)
      routes = ->(map) { (map || {}).select { |_, b| b.is_a?(Spf::Backups::Backup) } }
      was = routes.(before)
      now = routes.(after)
      (was.keys | now.keys).sort.filter_map do |prefix|
        old = was[prefix]
        new = now[prefix]
        family = prefix.include?(":") ? :ipv6 : :ipv4
        if new.nil?
          BackupOperation.new(kind: :withdraw, prefix: prefix, family: family, level: level)
        elsif old.nil? || old.adjacency != new.adjacency || old.labels != new.labels
          BackupOperation.new(kind: old ? :replace : :install, prefix: prefix, family: family,
                              adjacency: new.adjacency, labels: new.labels, level: level)
        end
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
