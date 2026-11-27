# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  # datalink-socket is a path dependency; add its lib too so tests run
  # without bundler.
  t.libs << "lib" << "test" << File.expand_path("../datalink-socket/lib", __dir__) << File.expand_path("../bfd4r", __dir__)
  t.test_files = FileList["test/unit/**/*_test.rb", "test/scenario/**/*_test.rb", "test/docs/**/*_test.rb", "test/exe/**/*_test.rb"]
  t.warning = false
end

# Interop tests against FRR's isisd, and against the Linux kernel's
# forwarding (kernel_*_test.rb). They need root, FRR and iproute2, and
# skip unless ISIS_FRR=1:
#
#   sudo env "PATH=$PATH" ISIS_FRR=1 rake interop
#
# Each file runs in a process of its own, ISIS_INTEROP_JOBS at a time (all
# of them by default; 1 runs them one after another), the largest first.
# Each file's labs are named for it and its pid, so two files never share
# a namespace, an FRR instance or a run directory. A file's output is
# printed whole when it ends, and the task fails if any file failed.
#
# TI-LFA's topologies on real routers (frr_ti_lfa_test.rb) took the FRR
# job from under 4 minutes to 9 to 11 in CI (2026-11-22), so they have a task of their own, interop_ti_lfa, and a
# CI job of their own.
TI_LFA_INTEROP = "test/interop/frr_ti_lfa_test.rb"

# The fault matrix (test/support/fault_matrix.rb): the interop tests that
# measure each group of the fault catalog, each recording what it found,
# then docs/fault-matrix.md written from it. As root, as interop:
#
#   sudo env "PATH=$PATH" ISIS_FRR=1 rake fault_matrix
# They are left out of `rake interop`: CI's interop (TI-LFA) job runs
# them, as `rake fault_matrix`, and keeps the document it writes.
FAULT_MATRIX = %w[test/interop/frr_sr_fault_test.rb test/interop/frr_ti_lfa_test.rb
                  test/interop/kernel_ti_lfa_test.rb test/interop/frr_flex_algo_topology_test.rb].freeze

desc "Run the FRR interop tests, one process per file, but the fault matrix's"
task :interop do
  run_interop(FileList["test/interop/**/frr_*_test.rb", "test/interop/**/kernel_*_test.rb"].exclude(*FAULT_MATRIX))
end

desc "Run TI-LFA's topologies on real routers, against FRR (needs what interop needs)"
task :interop_ti_lfa do
  run_interop(FileList[TI_LFA_INTEROP])
end

desc "Measure the fault catalog against isisd and FRR, and write docs/fault-matrix.md"
task :fault_matrix do
  require "tmpdir"
  require "etc"
  Dir.mktmpdir("isis-matrix") do |dir|
    ENV["ISIS_MATRIX_OUT"] = dir
    # One file at a time: ti_lfa_too_deep's 33 routers beside the other
    # files starved the CPUs and its repair never settled (2026-11-23).
    ENV["ISIS_INTEROP_JOBS"] ||= "1"
    failed = run_interop(FileList[*FAULT_MATRIX], abort_on_failure: false)
    $LOAD_PATH.unshift(*%w[lib test].map { File.expand_path(_1, __dir__) },
                       File.expand_path("../datalink-socket/lib", __dir__), File.expand_path("../bfd4r", __dir__))
    require "isis4r"
    require "support/fault_matrix"
    frr = `/usr/lib/frr/isisd --version 2>/dev/null`[/version (\S+)/, 1] || "not found"
    doc = FaultMatrix.render(FaultMatrix.load(dir), versions: "isis4r #{ISIS::VERSION}, Ruby #{RUBY_VERSION}, FRR #{frr}",
                                                    date: Time.now.utc.strftime("%F"), kernel: Etc.uname[:release])
    File.write(File.expand_path("docs/fault-matrix.md", __dir__), doc)
    puts "wrote docs/fault-matrix.md"
    abort "interop failed: #{failed.join(', ')}" unless failed.empty?
  end
end

def run_interop(list, abort_on_failure: true)
  require "rbconfig"
  require "tempfile"
  libs = ["lib", "test", File.expand_path("../datalink-socket/lib", __dir__), File.expand_path("../bfd4r", __dir__)].flat_map { |l| ["-I", l] }
  files = list.sort_by { |f| -File.size(f) }
  jobs = Integer(ENV.fetch("ISIS_INTEROP_JOBS", files.size.to_s)).clamp(1, files.size)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  queue = files.dup
  running = {}
  failed = []
  until queue.empty? && running.empty?
    while running.size < jobs && (file = queue.shift)
      out = Tempfile.new("interop")
      pid = Process.spawn(RbConfig.ruby, "-W0", *libs, file, %i[out err] => out.path)
      running[pid] = [file, out, Process.clock_gettime(Process::CLOCK_MONOTONIC)]
    end
    pid, status = Process.wait2
    file, out, t0 = running.delete(pid)
    took = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
    puts "==== #{file}: #{status.success? ? 'passed' : 'FAILED'} in #{took.round(1)} s", File.read(out.path)
    out.close!
    failed << file unless status.success?
  end
  puts "interop: #{files.size} files in #{(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(1)} s, " \
       "#{jobs} at a time"
  abort "interop failed: #{failed.join(', ')}" if abort_on_failure && !failed.empty?
  failed
end

# Interop tests against Nokia SR Linux, the second independent
# implementation. They need root, docker, containerlab and iproute2, and
# skip unless ISIS_SRL=1:
#
#   sudo env "PATH=$PATH" ISIS_SRL=1 rake interop_srl
Rake::TestTask.new(:interop_srl) do |t|
  t.libs << "lib" << "test" << File.expand_path("../datalink-socket/lib", __dir__) << File.expand_path("../bfd4r", __dir__)
  t.test_files = FileList["test/interop/**/srl_*_test.rb"]
  t.warning = false
end

task default: :test
