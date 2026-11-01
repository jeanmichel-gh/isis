# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  # datalink-socket is a path dependency; add its lib too so tests run
  # without bundler.
  t.libs << "lib" << "test" << File.expand_path("../datalink-socket/lib", __dir__)
  t.test_files = FileList["test/unit/**/*_test.rb", "test/docs/**/*_test.rb", "test/exe/**/*_test.rb"]
  t.warning = false
end

# Interop tests against FRR's isisd. They need root, FRR and iproute2, and
# skip unless ISIS_FRR=1:
#
#   sudo -E env "PATH=$PATH" ISIS_FRR=1 rake interop
Rake::TestTask.new(:interop) do |t|
  t.libs << "lib" << "test" << File.expand_path("../datalink-socket/lib", __dir__)
  t.test_files = FileList["test/integration/**/*_test.rb"]
  t.warning = false
end

task default: :test
