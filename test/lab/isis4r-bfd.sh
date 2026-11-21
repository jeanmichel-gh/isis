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
sleep 3

# AdminDown, RFC 5882 4.2: "If a BFD session transitions from Up state to
# AdminDown, or the session transitions from Up to Down because the
# remote system is indicating that the session is in state AdminDown,
# clients SHOULD NOT take any control protocol action."
# r1's adjacency lines in its log, and f1's flap count, before and after.
r1_lines() { docker logs "clab-isis4r-bfd-r1" 2>&1 | grep -cE "$1" || true; }
# Whether f1 had no adjacency Up at any moment of the next $1 seconds:
# "down" or "up", into $W/f1_watch. FRR's "Adjacency flaps" cannot say:
# FRR deletes the adjacency and makes a new one, whose count starts again.
# An answer without the table's header is no answer: vtysh may return
# nothing while the configuration changes.
f1_watch() {
  on f1 sh -c "end=\$((\$(date +%s) + $1)); while [ \$(date +%s) -lt \$end ]; do
    out=\$(vtysh -c 'show isis neighbor'); echo \"\$out\" | grep -q 'System Id' || continue
    echo \"\$out\" | grep -q ' Up ' || { echo down; echo \"\$out\"; exit; }; done; echo up" > "$W/f1_watch" &
  watcher=$!
  sleep 1
}
# Waits for the watcher, so not in a $( ), whose subshell cannot wait.
f1_watched() { wait "$watcher" || true; f1_seen=$(head -1 "$W/f1_watch"); }
r1_changes='eth1 adjacency with .* -> '
r1_drops='eth1 adjacency with .* -> down'

# f1's session AdminDown: r1 sees the remote AdminDown, and neither side
# acts. Six seconds is two of r1's hold times.
r1_before=$(r1_lines "$r1_changes"); f1_watch 8
f1_peer=(-c 'conf t' -c 'bfd' -c 'peer 10.0.12.1 local-address 10.0.12.2 interface eth1')
on f1 vtysh "${f1_peer[@]}" -c 'shutdown' >/dev/null
sleep 6
r1_after=$(r1_lines "$r1_changes"); f1_watched
on f1 vtysh "${f1_peer[@]}" -c 'no shutdown' -c 'exit' \
  -c 'no peer 10.0.12.1 local-address 10.0.12.2 interface eth1' >/dev/null
[ "$r1_after" = "$r1_before" ] || fail "r1's adjacency changed on f1's AdminDown (RFC 5882 4.2)"
[ "$f1_seen" = up ] || fail "f1's adjacency went Down on its own AdminDown: $(cat "$W/f1_watch")"
echo "ok: f1's session AdminDown, the adjacency stays Up on both"
eventually 60 r1_up "up/up" || fail "r1's BFD did not come back Up: $(r1_adjacency || true)"
sleep 3

# r1's session AdminDown. r1 must not act on it. FRR 10.2.1 does: its
# isisd logs "changed from Up to Down, bfd session went down" and sends
# TLV 240 Down, so r1 goes Up -> Initializing by RFC 5303 3.2's table
# and back Up on the next hellos (measured 2026-11-21). That is FRR's,
# against 4.2's SHOULD NOT, and expected here: the check fails when FRR
# stops doing it, so a fix in a newer FRR shows.
frr=$(vty "show version" | sed -n 's/^FRRouting \([^ ]*\).*/\1/p' | head -1)
r1_before=$(r1_lines "$r1_changes"); r1_drops_before=$(r1_lines "$r1_drops"); f1_watch 8
on r1 bfd4r-cli session.admin interface=eth1 peer=10.0.12.2 down=true >/dev/null
sleep 6
r1_after=$(r1_lines "$r1_changes"); r1_drops_after=$(r1_lines "$r1_drops"); f1_watched
on r1 bfd4r-cli session.admin interface=eth1 peer=10.0.12.2 down=false >/dev/null || true
[ "$r1_drops_after" = "$r1_drops_before" ] || fail "r1 took its adjacency Down on its own AdminDown (RFC 5882 4.2)"
if [ "$f1_seen" = up ]; then
  [ "$r1_after" = "$r1_before" ] || fail "r1's adjacency changed on its own AdminDown, and f1's did not (RFC 5882 4.2)"
  fail "FRR $frr no longer drops its adjacency on its peer's AdminDown: FRR fixed it. Update this check, ABOUT.md and CLAUDE.md"
fi
echo "ok: r1's session AdminDown, r1 takes no action of its own"
echo "known: FRR $frr drops its adjacency on its peer's AdminDown, against RFC 5882 4.2; r1 follows its TLV 240 Down"
eventually 60 r1_up "up/up" || fail "r1's adjacency did not come back with BFD: $(r1_adjacency || true)"
echo "ok: the adjacency and BFD are Up again"
cli show adjacencies
vty "show bfd peers brief"
[ "${KEEP_LAB:-}" ] || down
