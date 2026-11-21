# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "tmpdir"

# test/lab/bases.sh: the base images a build needs, tagged before the
# build, so BuildKit does not ask Docker Hub for them (its header says
# why). --list pulls nothing, so these need no Docker.
class TestLabBases < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  BASES = File.join(ROOT, "test/lab/bases.sh")

  def list(*args)
    out, status = Open3.capture2(BASES, "--list", *args)
    assert status.success?
    out.split
  end

  def test_args_stages_and_scratch
    Dir.mktmpdir do |dir|
      f = File.join(dir, "Dockerfile")
      File.write(f, <<~DOCKERFILE)
        ARG RUBY_VERSION=3.3
        FROM --platform=$BUILDPLATFORM node:22-slim AS web
        FROM ruby:${RUBY_VERSION}-slim AS base
        FROM base AS test
        from Test as router
        FROM scratch
        FROM ruby:$RUBY_VERSION-slim
      DOCKERFILE
      assert_equal %w[node:22-slim ruby:3.3-slim], list(f)
      assert_equal %w[node:22-slim ruby:3.4-slim], list("RUBY_VERSION=3.4", f)
    end
  end

  def test_our_dockerfile
    f = File.join(ROOT, "Dockerfile")
    skip "no Dockerfile here" unless File.file?(f)
    assert_match(/\Aruby:[\d.]+-slim\z/, list(f).first)
    assert_equal 1, list(f).size
  end

  # Every image build in a workflow tags its bases first, in its step.
  def test_every_workflow_build_tags_its_bases_first
    workflows = Dir[File.join(ROOT, ".github/workflows/*.yml")]
    skip "no .github here" if workflows.empty?
    workflows.each do |wf|
      lines = File.readlines(wf)
      lines.each_with_index do |line, i|
        next unless line.match?(/\bdocker build\b/) && !line.lstrip.start_with?("#")

        step = lines[0...i].rindex { _1.match?(/^\s*- (name|uses|run):/) }.to_i
        assert lines[step...i].any? { _1.include?("test/lab/bases.sh") },
               "#{File.basename(wf)}:#{i + 1} builds without test/lab/bases.sh before it"
      end
    end
  end
end
