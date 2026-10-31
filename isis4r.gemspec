# frozen_string_literal: true

require_relative "lib/isis/version"

Gem::Specification.new do |spec|
  spec.name = "isis4r"
  spec.version = ISIS::VERSION
  spec.authors = ["Jean-Michel Esnault"]

  spec.summary = "Build, parse and speak IS-IS in Ruby, for protocol testing."
  spec.description = <<~DESC
    A pure-Ruby IS-IS library for scripting IS-IS speakers in tests and
    research: build PDUs, including ones no standard allows, parse captures
    and replay them byte for byte, and put them on a link through
    datalink-socket.
  DESC
  spec.homepage = "https://github.com/jeanmichel-gh/isis"
  spec.licenses = ["GPL-3.0-or-later", "Ruby"]
  spec.required_ruby_version = ">= 3.1"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "exe/*",
    "README.md",
    "LICENSE*",
    "COPYING"
  ]
  spec.bindir = "exe"
  spec.executables = Dir["exe/*"].map { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "datalink-socket", "~> 1.0"

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
end
