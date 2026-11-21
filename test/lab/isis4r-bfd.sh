#!/bin/bash
# The isis4r-bfd interop lab, up, checked and down, in containerlab:
#
#   test/lab/isis4r-bfd.sh
#
# The gate of routescope docs/design/bfd-clients.md for isisd: BFD Up on
# both r1 (isis4r, bfdd4r) and f1 (FRR, bfdd), and the adjacency Up; then
# 100% loss on the link, with netem on both ends, and the adjacency Down
# in under a second on both, with reason bfd on r1. Each end's netem
# drops what it sends, so each side is timed from the moment its peer's
# netem goes on, the time taken in the peer just before its tc, to the
# moment it has no adjacency: r1 by isisd's log line, f1 by a loop on
# show isis neighbor. All to the millisecond, on the host's one clock.
# Then the loss is lifted and the adjacency comes back.
#
# Needs root, containerlab and the sch_netem module. ISIS4R_IMAGE runs
# another isis4r image than isis4r:latest. KEEP_LAB=1 leaves it up.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EX=$ROOT/routescope/labs/isis4r-bfd
W=${LAB_DIR:-/tmp/isis4r-bfd-lab}
IMAGE=${ISIS4R_IMAGE:-isis4r:latest}

on() { local n=$1; shift; docker exec "clab-isis4r-bfd-$n" "$@"; }
vty() { on f1 vtysh -c "$1"; }
cli() { on r1 isis-cli "$@"; }
# The lab's own files, with the image this run asks for.
up() {
  rm -rf "$W"; mkdir -p "$W"; cp -r "$EX"/. "$W"/
  sed -i "s#image: isis4r:latest#image: $IMAGE#" "$W/isis4r-bfd.clab.yml"
  (cd "$W" && containerlab deploy -t isis4r-bfd.clab.yml --reconfigure)
}
down() { [ -d "$W" ] && (cd "$W" && containerlab destroy -t isis4r-bfd.clab.yml --cleanup) || true; }
logs() { for n in r1 f1; do echo "--- $n"; docker logs --tail 60 "clab-isis4r-bfd-$n" 2>&1 || true; done; }

eventually() {
  local t=$1; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
r1_adjacency() { cli --json show adjacencies | ruby -rjson -e 'puts JSON.parse($stdin.read).map { "#{_1["state"]}/#{_1["bfd"]}" }.join(",")'; }
r1_up() { [ "$(r1_adjacency)" = "$1" ]; }
f1_up() { vty "show isis neighbor" | grep -q " Up "; }
f1_down() { ! vty "show isis neighbor" | grep -q " Up "; }
f1_bfd_up() { vty "show bfd peer 10.0.12.1 json" | grep -q '"status":"up"'; }
r1_down() { ! cli --json show adjacencies | grep -q '"state":"up"'; }

fail() { echo "FAIL: $1"; cli show adjacencies || true; vty "show bfd peers" || true; logs; [ "${KEEP_LAB:-}" ] || down; exit 1; }

down
up
eventually 90 r1_up "up/up" || fail "r1's adjacency is not Up with BFD Up: $(r1_adjacency || true)"
echo "ok: r1's adjacency is Up, with BFD Up"
eventually 30 f1_up || fail "f1's adjacency is not Up"
eventually 30 f1_bfd_up || fail "f1's BFD session to r1 is not Up"
echo "ok: f1's adjacency is Up, with BFD Up"
sleep 3

# f1 is timed from inside: a loop on vtysh, from before the loss, prints
# the time it first finds no adjacency Up. Its resolution is one vtysh
# call, tens of milliseconds; the time is python3's, the image's date has
# no milliseconds. (FRR's daemons share one log file and
# overwrite each other's lines, so its log cannot time it.)
on f1 sh -c 'while vtysh -c "show isis neighbor" | grep -q " Up "; do :; done; python3 -c "import time; print(\"%.3f\" % time.time())"' > "$W/f1_down" &
watcher=$!
sleep 1
# The loss on both ends, each time taken just before its tc.
r1_loss=$(on r1 sh -c 'date -u +%s.%3N; tc qdisc add dev eth1 root netem loss 100%')
f1_loss=$(on f1 sh -c 'python3 -c "import time; print(\"%.3f\" % time.time())"; tc qdisc add dev eth1 root netem loss 100%')
eventually 10 r1_down || fail "r1's adjacency did not go Down"
eventually 10 f1_down || fail "f1's adjacency did not go Down"
sleep 1

# r1: isisd's log line, "TIME info  eth1 adjacency with ... up -> down: BFD session ...".
r1_line=$(docker logs "clab-isis4r-bfd-r1" 2>&1 | grep -E 'adjacency with .* up -> down: BFD session' | tail -1)
[ -n "$r1_line" ] || fail "no adjacency down for BFD in r1's log"
r1_at=$(echo "$r1_line" | ruby -rtime -e 'puts format("%.3f", Time.iso8601($stdin.read.split.first).to_f)')
# r1's event says reason bfd.
cli --json call show.log '{"count": 200}' | ruby -rjson -e '
  rows = JSON.parse($stdin.read); rows = rows["result"] if rows.is_a?(Hash)
  e = rows.reverse.find { _1["kind"] == "adjacency" && _1.dig("data", "to") == "down" }
  abort "no adjacency down event" unless e
  abort "reason is #{e.dig("data", "reason").inspect}" unless e.dig("data", "reason") == "bfd"
  puts "ok: r1 event: #{e["message"]}"' || fail "r1's adjacency event does not say reason bfd"
wait "$watcher" || true
f1_at=$(cat "$W/f1_down")
[ -n "$f1_at" ] || fail "f1's watcher saw no adjacency go Down"
f1_line="no adjacency Up in show isis neighbor at $f1_at"

# r1 hears nothing once f1's netem is on, and f1 once r1's is.
r1_took=$(ruby -e "puts format('%.3f', $r1_at - $f1_loss)")
f1_took=$(ruby -e "puts format('%.3f', $f1_at - $r1_loss)")
echo "loss from r1 at $r1_loss, from f1 at $f1_loss"
echo "r1 down at $r1_at, ${r1_took} s after f1's loss; f1 down at $f1_at, ${f1_took} s after r1's loss"
echo "r1: $r1_line"
echo "f1: $f1_line"
ruby -e "exit($r1_took < 1.0)" || fail "r1 took ${r1_took} s, not under a second"
ruby -e "exit($f1_took < 1.0)" || fail "f1 took ${f1_took} s, not under a second"
echo "ok: the adjacency went Down in under a second on both, reason bfd on r1"

on r1 tc qdisc del dev eth1 root
on f1 tc qdisc del dev eth1 root
eventually 60 r1_up "up/up" || fail "r1's adjacency did not come back with BFD: $(r1_adjacency || true)"
echo "ok: with the loss lifted, the adjacency and BFD are Up again"
cli show adjacencies
vty "show bfd peers brief"
[ "${KEEP_LAB:-}" ] || down
