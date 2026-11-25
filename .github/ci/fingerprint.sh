#!/bin/sh
# Prints the fingerprint of what CI tests: every file of the checked-out
# tree but those no test reads, CLAUDE.md and docs/design/, and the
# commits of the two repositories CI checks out beside it, datalink-socket
# and bfd4r, from their default branches. A run that passed records it
# (the ci job); a later run with the same fingerprint would test the same
# thing, so its test jobs are skipped (the changes job).
#
# Nothing under test/, lib/, exe/ or the Rakefile reads CLAUDE.md or
# docs/design/; test/docs reads only docs/*.md, which stay in the
# fingerprint. test/unit/ci_fingerprint_test.rb holds that.
set -eu
tree=$(git ls-tree -r HEAD | awk -F'\t' '$2 != "CLAUDE.md" && $2 !~ /^docs\/design\//')
deps=""
for repo in datalink-socket bfd4r; do
  sha=$(git ls-remote "https://github.com/jeanmichel-gh/$repo" HEAD | cut -f1)
  [ -n "$sha" ] || { echo "no HEAD for $repo" >&2; exit 1; }
  deps="$deps$repo $sha
"
done
printf '%s\n%s' "$tree" "$deps" | git hash-object --stdin
