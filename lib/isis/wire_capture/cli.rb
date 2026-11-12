# frozen_string_literal: true
require 'json'
require 'time'
require 'optparse'
require_relative 'pcap'
require_relative 'dissect'

module ISIS
  module WireCapture
    class CLI
      def initialize(out = $stdout)
        @out = out
      end

      def run(argv)
        argv = argv.dup
        argv.shift if argv.first == 'capture'
        options = { interface: 'eth0', file: nil, count: nil }
        OptionParser.new do |o|
          o.on('-i IFACE') { options[:interface] = _1 }
          o.on('-r FILE') { options[:file] = _1 }
          o.on('-c N', Integer) { options[:count] = _1 }
        end.parse!(argv)
        @out.sync = true if @out.respond_to?(:sync=)
        if options[:file]
          io = options[:file] == '-' ? $stdin.binmode : File.open(options[:file], 'rb')
        else
          io, writer = IO.pipe
          pid = Process.spawn('tcpdump', '-U', '-n', '-s', '0', '-w', '-', '-i', options[:interface], 'isis', out: writer, err: $stderr)
          writer.close
        end
        reader = Pcap::Reader.new(io)
        raise ArgumentError, "IS-IS capture requires Ethernet, got link type #{reader.link}" unless reader.link == 1
        @out.puts JSON.generate(capture: { interface: options[:interface], filter: 'isis', link: 'ethernet', unit: 'frame' })
        seq = 0
        reader.each do |record|
          seq += 1
          packet = Dissect.frame(record.data).merge(seq: seq, time: record.time.utc.iso8601(6), hex: record.data.unpack1('H*'), length: record.length)
          @out.puts JSON.generate(packet: packet)
          break if options[:count] && seq >= options[:count]
        end
        0
      rescue StandardError => error
        @out.puts JSON.generate(error: "#{error.class}: #{error.message}")
        1
      ensure
        writer&.close unless writer&.closed?
        if pid
          Process.kill('TERM', pid) rescue nil
          Process.wait(pid) rescue nil
        end
        io&.close unless io == $stdin || io&.closed?
      end
    end
  end
end
