#!/bin/bash
# The isis4r-areas example lab, up, checked and down, two ways:
#
#   test/lab/isis4r-areas.sh clab     containerlab, the isis4r image
#   test/lab/isis4r-areas.sh netns    network namespaces, this checkout's
#                                     isisd and isis4r-sim, no Docker
#
# Both use the example's own files, isisd.yml and sim.yml, and run the
# same checks: each border's two Level 2 adjacencies, each r's default
# route to its border (the attached bit), b2's route to area 1's r3c3
# over b1, then through b3 while b1:eth1 is down. r1 pings r2's loopback
# across the backbone: in netns mode with the host's ping, in clab mode
# when the image has one (isis4r PR #71 adds it).
# Needs root. KEEP_LAB=1 leaves it up.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EX=$ROOT/examples/containerlab/isis4r-areas
MODE=${1:?usage: isis4r-areas.sh clab|netns}
W=${LAB_DIR:-/tmp/isis4r-areas-lab}
NODES="b1 b2 b3 r1 r2 r3 s1 s2 s3"

case $MODE in
clab)
  on() { local n=$1; shift; docker exec "clab-isis4r-areas-$n" "$@"; }
  cli() { local n=$1; shift; on "$n" isis-cli "$@"; }
  up() { (cd "$EX" && containerlab deploy -t isis4r-areas.clab.yml --reconfigure); }
  down() { (cd "$EX" && containerlab destroy -t isis4r-areas.clab.yml --cleanup) || true; }
  logs() { for n in $NODES; do echo "--- $n"; docker logs --tail 20 "clab-isis4r-areas-$n" 2>&1 || true; done; }
  # ping is in the image from isis4r PR #71; an older image has none.
  can_ping() { on r1 sh -c "command -v ping" >/dev/null 2>&1; }
  ;;
netns)
  on() { local n=$1; shift; ip netns exec "isis4r-areas-$n" "$@"; }
  cli() { local n=$1; shift; ruby -I"$ROOT/lib" "$ROOT/exe/isis-cli" -s "$W/$n.sock" "$@"; }
  down() {
    for n in $NODES; do [ -f "$W/$n.pid" ] && kill "$(cat "$W/$n.pid")" 2>/dev/null || true; done
    sleep 1
    for n in $NODES; do ip netns del "isis4r-areas-$n" 2>/dev/null || true; done
  }
  # A veth pair between two namespaces, both ends up.
  wire() {
    local a=${1%:*} ai=${1#*:} b=${2%:*} bi=${2#*:}
    ip link add "$ai" netns "isis4r-areas-$a" type veth peer name "$bi" netns "isis4r-areas-$b"
    on "$a" ip link set "$ai" up; on "$b" ip link set "$bi" up
  }
  # The links as containerlab wires them, the addresses as the topology's
  # cmd lines set them.
  up() {
    rm -rf "$W"; mkdir -p "$W"
    for n in $NODES; do ip netns add "isis4r-areas-$n"; on $n ip link set lo up; done
    wire b1:eth1 b2:eth1; wire b2:eth2 b3:eth1; wire b1:eth2 b3:eth2
    for i in 1 2 3; do wire b$i:eth3 s$i:eth1; wire b$i:eth4 r$i:eth1; wire r$i:eth2 s$i:eth2; done
    on b1 ip addr add 10.0.12.1/30 dev eth1; on b1 ip addr add 10.0.13.1/30 dev eth2
    on b2 ip addr add 10.0.12.2/30 dev eth1; on b2 ip addr add 10.0.23.1/30 dev eth2
    on b3 ip addr add 10.0.23.2/30 dev eth1; on b3 ip addr add 10.0.13.2/30 dev eth2
    for i in 1 2 3; do
      on b$i ip addr add 10.$i.0.1/30 dev eth3; on b$i ip addr add 10.$i.1.1/30 dev eth4
      on b$i ip addr add 10.255.0.$i/32 dev lo
      on r$i ip addr add 10.$i.1.2/30 dev eth1; on r$i ip addr add 10.$i.2.1/30 dev eth2
      on r$i ip addr add 10.255.0.2$i/32 dev lo
      on s$i ip addr add 10.$i.0.2/30 dev eth1; on s$i ip addr add 10.$i.2.2/30 dev eth2
      on s$i ip addr add 10.255.0.1$i/32 dev lo
    done
    for n in b1 b2 b3 r1 r2 r3; do
      on $n sysctl -qw net.ipv4.ip_forward=1
      on $n ruby -I"$ROOT/lib" -I"$ROOT/../datalink-socket/lib" "$ROOT/exe/isisd" -c "$EX/$n/isisd.yml" \
        -s "$W/$n.sock" -l "$W/$n.log" > "$W/$n.out" 2>&1 &
      echo $! > "$W/$n.pid"
    done
    for n in s1 s2 s3; do
      on $n ruby -I"$ROOT/lib" -I"$ROOT/../datalink-socket/lib" "$ROOT/exe/isis4r-sim" -c "$EX/$n/sim.yml" \
        -s "$W/$n.sock" -l "$W/$n.log" > "$W/$n.out" 2>&1 &
      echo $! > "$W/$n.pid"
    done
  }
  logs() { for n in $NODES; do echo "--- $n"; tail -20 "$W/$n.log" "$W/$n.out" 2>/dev/null || true; done; }
  can_ping() { true; }
  ;;
*) echo "usage: isis4r-areas.sh clab|netns" >&2; exit 2 ;;
esac

# Wait up to $1 seconds for the command after it to succeed.
eventually() {
  local t=$1; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
# Adjacencies up at a level, from isis-cli.
ups() {
  cli "$1" --json show adjacencies |
    ruby -rjson -e "puts JSON.parse(\$stdin.read).count { _1['state'] == 'up' && _1['level'] == $2 }"
}
l2_ring() { for b in b1 b2 b3; do [ "$(ups $b 2)" = 2 ] || return 1; done; }
defaults() { for i in 1 2 3; do on r$i ip route show 0.0.0.0/0 | grep -q "via 10.$i.1.1" || return 1; done; }
b2_to_area1() { on b2 ip route show exact 10.201.0.9/32 | grep -q "via $1"; }
r1_pings_r2() { on r1 ping -c 1 -W 1 -I 10.255.0.21 10.255.0.22; }

fail() {
  echo "FAIL: $1"
  for n in b1 b2 r1; do echo "--- $n"; cli $n show adjacencies || true; done
  logs; [ "${KEEP_LAB:-}" ] || down; exit 1
}

down
up
eventually 90 l2_ring || fail "the borders do not have two Level 2 adjacencies each"
echo "ok: each border has two Level 2 adjacencies, and Level 1 only inside its area"
eventually 60 defaults || fail "an r has no default route to its border"
echo "ok: each r has a default route to its border, by the attached bit"
eventually 60 b2_to_area1 10.0.12.1 || fail "b2 has no route to 10.201.0.9/32 over b1"
echo "ok: b2 reaches area 1's r3c3 over b1"
if can_ping; then
  eventually 30 r1_pings_r2 || fail "r1 does not reach r2's loopback"
  echo "ok: r1 pings r2's loopback, by default routes and Level 2"
else
  echo "skip: no ping in the image, so r1 to r2 is not pinged"
fi
on b1 ip link set eth1 down
eventually 20 b2_to_area1 10.0.23.2 || fail "b2 does not reroute through b3 with b1:eth1 down"
echo "ok: with b1:eth1 down, b2 reaches area 1 through b3"
on b1 ip link set eth1 up
eventually 30 b2_to_area1 10.0.12.1 || fail "b2 does not go back over b1"
echo "ok: b1:eth1 up, and b2 is back over b1"
cli b2 show routes
[ "${KEEP_LAB:-}" ] || down
