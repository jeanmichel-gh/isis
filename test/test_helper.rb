# frozen_string_literal: true

# The library is under lib/, laid out as CLAUDE.md describes.
# datalink-socket is a path dependency during the PoC. Add
# both to the load path so tests run without bundler (and without network).
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../datalink-socket/lib", __dir__)

require "minitest/autorun"
require "isis4r"
require "datalink/backends/loopback"
