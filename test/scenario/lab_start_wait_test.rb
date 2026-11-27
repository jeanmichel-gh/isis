# frozen_string_literal: true

require_relative "../test_helper"
require "yaml"

# A lab node's start command waits for its interfaces, then gives them
# their addresses and starts isisd. containerlab wires the links in the
# order the file lists them, so the wait must be on the node's interface
# of the last link it is on. A wait on an earlier one lets the command
# run on before the last interface exists: "Cannot find device", no
# address, and no BFD on that link (bfd-lab's r3, 2026-11-22).
class TestLabStartWait < Minitest::Test
  LABS = File.expand_path("../../routescope/labs", __dir__)

  def test_every_node_waits_for_its_last_wired_interface
    files = Dir[File.join(LABS, "*", "*.clab.yml")].sort
    refute_empty files

    checked = 0
    files.each do |file|
      topology = YAML.load_file(file).fetch("topology")
      wired = Hash.new { |h, k| h[k] = [] }
      topology.fetch("links").each do |link|
        link.fetch("endpoints").each do |end_point|
          node, interface = end_point.split(":")
          wired[node] << interface
        end
      end

      topology.fetch("nodes").each do |node, config|
        cmd = config["cmd"].to_s
        waits = cmd.scan(/until ip link show (\S+)/).flatten
        # `for i in eth1 eth2; do until ip link show $i ...` waits for each.
        waits += cmd.scan(/for (\w+) in ([\w ]+?); do until ip link show \$\1\b/).flat_map { |_, list| list.split }
        # A node that gives an interface an address waits first: a command
        # with no wait gave isis4r-tilfa's s1 none ("-c \"1 ip addr add").
        addresses = cmd.scan(/ip addr add \S+ dev (eth\d+)/).flatten
        refute(waits.empty? && !addresses.empty?,
               "#{File.basename(file)} #{node} gives #{addresses.join(", ")} an address without waiting for them")
        next if waits.empty?

        checked += 1
        last = wired[node].last
        assert_includes waits, last,
                        "#{File.basename(file)} #{node} waits for #{waits.join(", ")}, " \
                        "but containerlab wires #{last} last (links: #{wired[node].join(", ")})"
      end
    end
    assert_operator checked, :>, 0
  end
end
