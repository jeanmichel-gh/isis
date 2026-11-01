# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  # datalink-socket is a path dependency; add its lib too so tests run
  # without bundler.
  t.libs << "lib" << "test" << File.expand_path("../datalink-socket/lib", __dir__)
  t.test_files = FileList["test/unit/**/*_test.rb", "test/docs/**/*_test.rb", "test/exe/**/*_test.rb"]
  t.warning = false
end

task default: :test
