#!/bin/bash
# The isis4r-areas-core example lab, up, checked and down, two ways:
#
#   test/lab/isis4r-areas-core.sh clab     containerlab, the isis4r image
#   test/lab/isis4r-areas-core.sh netns    network namespaces, this
#                                          checkout's isisd and isis4r-sim,
#                                          no Docker
#
# Both use the example's own files and run the same checks: c0's three
# Level 2 adjacencies and b3's one, each r's default route to its border,
# b3's route to area 1's r3c3 through c0; b1 leaking area 3 into r1's
# kernel, then not; c0 overloaded, so b3 loses area 1; b2 through c0 while
# b1:eth2 is down. r1 pings r3 through c0: in netns mode with the host's
# ping, in clab mode when the image has one.
# Needs root. KEEP_LAB=1 leaves it up. DATALINK_SOCKET names the
# datalink-socket checkout, ../datalink-socket by default.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EX=$ROOT/routescope/labs/isis4r-areas-core
MODE=${1:?usage: isis4r-areas-core.sh clab|netns}
W=${LAB_DIR:-/tmp/isis4r-areas-core-lab}
NODES="c0 b1 b2 b3 r1 r2 r3 s1 s2 s3"
# datalink-socket beside the checkout, or where DATALINK_SOCKET says.
DLS=${DATALINK_SOCKET:-$ROOT/../datalink-socket}
ROUTERS="c0 b1 b2 b3 r1 r2 r3"

case $MODE in
clab)
  on() { local n=$1; shift; docker exec "clab-isis4r-areas-core-$n" "$@"; }
  cli() { local n=$1; shift; on "$n" isis-cli "$@"; }
  up() { (cd "$EX" && containerlab deploy -t isis4r-areas-core.clab.yml --reconfigure); }
  down() { (cd "$EX" && containerlab destroy -t isis4r-areas-core.clab.yml --cleanup) || true; }
  logs() { for n in $NODES; do echo "--- $n"; docker logs --tail 20 "clab-isis4r-areas-core-$n" 2>&1 || true; done; }
  can_ping() { on r1 sh -c "command -v ping" >/dev/null 2>&1; }
  ;;
netns)
  on() { local n=$1; shift; ip netns exec "isis4r-ac-$n" "$@"; }
  cli() { local n=$1; shift; ruby -I"$ROOT/lib" "$ROOT/exe/isis-cli" -s "$W/$n.sock" "$@"; }
  down() {
    for n in $NODES; do [ -f "$W/$n.pid" ] && kill "$(cat "$W/$n.pid")" 2>/dev/null || true; done
    sleep 1
    for n in $NODES; do ip netns del "isis4r-ac-$n" 2>/dev/null || true; done
  }
  # A veth pair between two namespaces, both ends up.
  wire() {
    local a=${1%:*} ai=${1#*:} b=${2%:*} bi=${2#*:}
    ip link add "$ai" netns "isis4r-ac-$a" type veth peer name "$bi" netns "isis4r-ac-$b"
    on "$a" ip link set "$ai" up; on "$b" ip link set "$bi" up
  }
  # The links and addresses as the clab file sets them.
  up() {
    rm -rf "$W"; mkdir -p "$W"
    for n in $NODES; do ip netns add "isis4r-ac-$n"; on $n ip link set lo up; done
    wire c0:eth1 b1:eth1; wire c0:eth2 b2:eth1; wire c0:eth3 b3:eth1; wire b1:eth2 b2:eth2
    for i in 1 2 3; do wire b$i:eth3 s$i:eth1; wire b$i:eth4 r$i:eth1; wire r$i:eth2 s$i:eth2; done
    on c0 ip addr add 10.0.1.1/30 dev eth1; on c0 ip addr add 10.0.2.1/30 dev eth2
    on c0 ip addr add 10.0.3.1/30 dev eth3; on c0 ip addr add 10.255.0.100/32 dev lo
    on b1 ip addr add 10.0.1.2/30 dev eth1; on b1 ip addr add 10.0.12.1/30 dev eth2
    on b2 ip addr add 10.0.2.2/30 dev eth1; on b2 ip addr add 10.0.12.2/30 dev eth2
    on b3 ip addr add 10.0.3.2/30 dev eth1
    for i in 1 2 3; do
      on b$i ip addr add 10.$i.0.1/30 dev eth3; on b$i ip addr add 10.$i.1.1/30 dev eth4
      on b$i ip addr add 10.255.0.$i/32 dev lo
      on r$i ip addr add 10.$i.1.2/30 dev eth1; on r$i ip addr add 10.$i.2.1/30 dev eth2
      on r$i ip addr add 10.255.0.2$i/32 dev lo
      on s$i ip addr add 10.$i.0.2/30 dev eth1; on s$i ip addr add 10.$i.2.2/30 dev eth2
      on s$i ip addr add 10.255.0.1$i/32 dev lo
    done
    for n in $ROUTERS; do
      on $n sysctl -qw net.ipv4.ip_forward=1
      on $n ruby -I"$ROOT/lib" -I"$DLS/lib" "$ROOT/exe/isisd" -c "$EX/$n/isisd.yml" \
        -s "$W/$n.sock" -l "$W/$n.log" > "$W/$n.out" 2>&1 &
      echo $! > "$W/$n.pid"
    done
    for n in s1 s2 s3; do
      on $n ruby -I"$ROOT/lib" -I"$DLS/lib" "$ROOT/exe/isis4r-sim" -c "$EX/$n/sim.yml" \
        -s "$W/$n.sock" -l "$W/$n.log" > "$W/$n.out" 2>&1 &
      echo $! > "$W/$n.pid"
    done
  }
  logs() { for n in $NODES; do echo "--- $n"; tail -20 "$W/$n.log" "$W/$n.out" 2>/dev/null || true; done; }
  can_ping() { true; }
  ;;
*) echo "usage: isis4r-areas-core.sh clab|netns" >&2; exit 2 ;;
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
backbone() { [ "$(ups c0 2)" = 3 ] && [ "$(ups c0 1)" = 0 ] && [ "$(ups b3 2)" = 1 ]; }
defaults() { for i in 1 2 3; do on r$i ip route show 0.0.0.0/0 | grep -q "via 10.$i.1.1" || return 1; done; }
# A kernel route: $1 node, $2 prefix, $3 next hop.
via() { on "$1" ip route show exact "$2" | grep -q "via $3"; }
gone() { ! on "$1" ip route show exact "$2" | grep -q .; }
r1_pings_r3() { on r1 ping -c 1 -W 1 -I 10.255.0.21 10.255.0.23; }

fail() {
  echo "FAIL: $1"
  for n in c0 b1 b3 r1; do echo "--- $n"; cli $n show adjacencies || true; done
  logs; [ "${KEEP_LAB:-}" ] || down; exit 1
}

down
up
eventually 90 backbone || fail "c0 has not three Level 2 adjacencies and no Level 1, or b3 not one"
echo "ok: c0 at Level 2 only, with the three borders; b3 with c0 only"
eventually 60 defaults || fail "an r has no default route to its border"
echo "ok: each r has a default route to its border, by the attached bit"
eventually 60 via b3 10.201.0.9/32 10.0.3.1 || fail "b3 has no route to area 1 through c0"
echo "ok: b3 reaches area 1's r3c3 through c0"
if can_ping; then
  eventually 30 r1_pings_r3 || fail "r1 does not reach r3's loopback"
  echo "ok: r1 pings r3 through c0"
else
  echo "skip: no ping in the image, so r1 to r3 is not pinged"
fi

cli b1 call policy.leak '{"prefixes": ["10.203.0.0/24"]}'
eventually 20 via r1 10.203.0.9/32 10.1.1.1 || fail "b1 leaks nothing of area 3 into r1"
echo "ok: b1 leaks area 3 into area 1, and r1 installs it"
cli b1 call policy.leak '{"prefixes": []}'
eventually 20 gone r1 10.203.0.9/32 || fail "r1 keeps the leaked route after the leak is cleared"
echo "ok: the leak cleared, r1 back to its default"

cli c0 call policy.overload '{"on": true}'
eventually 20 gone b3 10.201.0.9/32 || fail "b3 still reaches area 1 with c0 overloaded"
echo "ok: c0 overloaded, b3 loses area 1"
cli c0 call policy.overload '{"on": false}'
eventually 20 via b3 10.201.0.9/32 10.0.3.1 || fail "b3 does not get area 1 back"
echo "ok: c0 not overloaded, b3 reaches area 1 again"

on b1 ip link set eth2 down
eventually 20 via b2 10.201.0.9/32 10.0.2.1 || fail "b2 does not reroute through c0 with b1:eth2 down"
echo "ok: with b1:eth2 down, b2 reaches area 1 through c0"
on b1 ip link set eth2 up
eventually 30 via b2 10.201.0.9/32 10.0.12.1 || fail "b2 does not go back over b1"
echo "ok: b1:eth2 up, and b2 is back over b1"
cli b2 show routes
[ "${KEEP_LAB:-}" ] || down
