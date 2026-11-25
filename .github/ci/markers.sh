#!/bin/sh
# Fails when a tracked file holds a line git writes for a conflict:
# <<<<<<<, ======= or >>>>>>>, at the start of a line. A conflict resolved
# by hand leaves none, so a run that reuses an earlier pass (fingerprint.sh)
# still checks the resolution of the files the fingerprint leaves out.
set -eu
if git grep -nE '^(<<<<<<<|>>>>>>>)( |$)|^=======$' -- .; then
  echo "conflict markers left in the files above" >&2
  exit 1
fi
