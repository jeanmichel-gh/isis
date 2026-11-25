# frozen_string_literal: true

require_relative "../test_helper"

# CI skips its test jobs when a run with the same fingerprint passed
# (.github/ci/fingerprint.sh). The fingerprint leaves out CLAUDE.md and
# docs/design/, so no code may read them: a change there must not be able
# to change a test's result.
class TestCiFingerprint < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  LEFT_OUT = %r{CLAUDE\.md|docs/design}

  # What opens a file by name.
  READS = /File\.(read|readlines|open|foreach|expand_path|join)|IO\.read|Dir\[|Dir\.glob|__dir__/

  def sources
    # The lab image (Dockerfile) copies lib, exe and test, not the Rakefile.
    rakefile = File.join(ROOT, "Rakefile")
    (Dir[File.join(ROOT, "{lib,exe,test,bin}/**/*.rb")] + (File.exist?(rakefile) ? [rakefile] : [])) - [__FILE__]
  end

  # A line that opens a file and names a left-out one, outside a comment.
  def test_no_code_reads_what_the_fingerprint_leaves_out
    found = sources.flat_map do |path|
      File.readlines(path).each_with_index.filter_map do |line, i|
        code = line.sub(/#.*/, "")
        "#{path.delete_prefix("#{ROOT}/")}:#{i + 1}: #{line.strip}" if code.match?(READS) && code.match?(LEFT_OUT)
      end
    end
    assert_empty found, "code reads a file the CI fingerprint leaves out; add it to .github/ci/fingerprint.sh"
  end

  # The lab image has no .github; the repository's runs check this.
  def test_the_script_leaves_out_what_this_test_checks
    path = File.join(ROOT, ".github/ci/fingerprint.sh")
    skip "no .github here, as in the lab image" unless File.exist?(path)
    script = File.read(path)
    assert_includes script, '$2 != "CLAUDE.md"'
    assert_includes script, '$2 !~ /^docs\/design\//'
  end
end
