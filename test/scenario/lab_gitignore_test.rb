# frozen_string_literal: true

require_relative "../test_helper"

# Each lab under routescope/labs keeps routescope's and containerlab's
# runtime state out of git. Without a .gitignore, routescope writes one
# itself, as root, on the lab's first scenario run (isis4r-flexalgo on
# ospflab, 2026-11-27), and the checkout gains an untracked file.
class TestLabGitignore < Minitest::Test
  LABS = File.expand_path("../../routescope/labs", __dir__)

  def test_every_lab_ignores_its_runtime_state
    labs = Dir[File.join(LABS, "*", "*.clab.yml")].map { File.dirname(_1) }.sort
    refute_empty labs
    labs.each do |lab|
      file = File.join(lab, ".gitignore")
      assert File.file?(file), "#{File.basename(lab)} has no .gitignore"
      lines = File.readlines(file, chomp: true)
      assert_empty %w[recordings/ clab-*/] - lines, "#{File.basename(lab)}'s .gitignore"
    end
  end
end
