#!/bin/bash
# The isis4r-frr example lab, up, checked and down, two ways:
#
#   test/lab/isis4r-frr.sh clab     containerlab, the isis4r and FRR images
#   test/lab/isis4r-frr.sh netns    network namespaces, this checkout's
#                                   isisd and the host's FRR, no Docker
#
# Both use the example's own files, isisd.yml and frr.conf, and run the
# same checks: isis4r's two adjacencies up, f1's default route through
# isis4r (the attached bit), f2's route to f1's loopback through isis4r
# (area 49.0001 into Level 2), and f1 pinging f2's loopback through
# isis4r's installed routes. Needs root. KEEP_LAB=1 leaves it up.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EX=$ROOT/examples/containerlab/isis4r-frr
MODE=${1:?usage: isis4r-frr.sh clab|netns}
W=${LAB_DIR:-/tmp/isis4r-frr-lab}

case $MODE in
clab)
  on() { local n=$1; shift; docker exec "clab-isis4r-frr-$n" "$@"; }
  vty() { on "$1" vtysh -c "$2"; }
  cli() { on r1 isis-cli "$@"; }
  up() { (cd "$EX" && containerlab deploy -t isis4r-frr.clab.yml --reconfigure); }
  down() { (cd "$EX" && containerlab destroy -t isis4r-frr.clab.yml --cleanup) || true; }
  logs() { for n in r1 f1 f2; do echo "--- $n"; docker logs --tail 40 "clab-isis4r-frr-$n" 2>&1 || true; done; }
  ;;
netns)
  FRR=${FRR:-/usr/lib/frr}
  on() { local n=$1; shift; ip netns exec "isis4r-frr-$n" "$@"; }
  vty() { vtysh -N "isis4r-frr-$1" -c "$2" 2>/dev/null; }
  cli() { ruby "$ROOT/exe/isis-cli" -s "$W/isisd.sock" "$@"; }
  down() {
    for n in f1 f2; do for d in isisd zebra; do
      p=/run/frr/isis4r-frr-$n/$d.pid; [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true
    done; done
    [ -f "$W/isisd.pid" ] && kill "$(cat "$W/isisd.pid")" 2>/dev/null || true
    sleep 1
    for n in r1 f1 f2; do ip netns del "isis4r-frr-$n" 2>/dev/null || true; done
    rm -rf /run/frr/isis4r-frr-f1 /run/frr/isis4r-frr-f2 /etc/frr/isis4r-frr-f1 /etc/frr/isis4r-frr-f2
  }
  # The links as containerlab wires them, the addresses as the topology's
  # cmd and exec set them.
  up() {
    rm -rf "$W"; mkdir -p "$W"
    for n in r1 f1 f2; do ip netns add "isis4r-frr-$n"; on $n ip link set lo up; done
    ip link add eth1 netns isis4r-frr-r1 type veth peer name eth1 netns isis4r-frr-f1
    ip link add eth2 netns isis4r-frr-r1 type veth peer name eth1 netns isis4r-frr-f2
    on r1 ip link set eth1 up; on r1 ip link set eth2 up; on f1 ip link set eth1 up; on f2 ip link set eth1 up
    on r1 ip addr add 10.0.12.1/30 dev eth1; on r1 ip addr add 10.0.13.1/30 dev eth2
    on r1 ip addr add 10.255.0.1/32 dev lo; on r1 sysctl -qw net.ipv4.ip_forward=1
    on f1 ip addr add 10.0.12.2/30 dev eth1; on f1 ip addr add 10.255.0.2/32 dev lo
    on f2 ip addr add 10.0.13.2/30 dev eth1; on f2 ip addr add 10.255.0.3/32 dev lo
    for n in f1 f2; do
      local etc=/etc/frr/isis4r-frr-$n run=/run/frr/isis4r-frr-$n
      mkdir -p "$etc" "$run"
      # zebra gets a file of its own: given isisd's, it rejects the IS-IS lines.
      printf 'hostname %s\nip forwarding\n' $n > "$etc/zebra.conf"
      cp "$EX/$n/frr.conf" "$etc/isisd.conf"
      chown -R frr:frr "$etc" "$run"
      on $n sysctl -qw net.ipv4.ip_forward=1
      on $n "$FRR/zebra" -N "isis4r-frr-$n" -d -f "$etc/zebra.conf" -i "$run/zebra.pid" >/dev/null 2>&1
      on $n "$FRR/isisd" -N "isis4r-frr-$n" -d -f "$etc/isisd.conf" -i "$run/isisd.pid" >/dev/null 2>&1
    done
    on r1 ruby -I"$ROOT/lib" -I"$ROOT/../datalink-socket/lib" "$ROOT/exe/isisd" -c "$EX/r1/isisd.yml" \
      -s "$W/isisd.sock" -l "$W/isisd.log" > "$W/isisd.out" 2>&1 &
    echo $! > "$W/isisd.pid"
  }
  logs() { tail -40 "$W/isisd.log" "$W/isisd.out" 2>/dev/null || true; }
  ;;
*) echo "usage: isis4r-frr.sh clab|netns" >&2; exit 2 ;;
esac

# Wait up to $1 seconds for the command after it to succeed.
eventually() {
  local t=$1; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
two_up() { [ "$(cli --json show adjacencies | ruby -rjson -e 'puts JSON.parse($stdin.read).count { _1["state"] == "up" }')" = 2 ]; }
f1_default() { vty f1 "show ip route 0.0.0.0/0" | grep -q "10.0.12.1"; }
f2_reaches_f1() { vty f2 "show ip route 10.255.0.2/32" | grep -q "10.0.13.1"; }
f1_pings_f2() { on f1 ping -c 1 -W 1 -I 10.255.0.2 10.255.0.3; }

fail() { echo "FAIL: $1"; cli show adjacencies || true; cli show routes || true; logs; [ "${KEEP_LAB:-}" ] || down; exit 1; }

down
up
eventually 60 two_up || fail "isis4r's two adjacencies are not up"
echo "ok: isis4r has its two adjacencies up"
eventually 60 f1_default || fail "f1 has no default route through isis4r"
echo "ok: f1 has a default route through isis4r, by the attached bit"
eventually 60 f2_reaches_f1 || fail "f2 has no route to f1's loopback through isis4r"
echo "ok: f2 reaches f1's loopback through isis4r, area 49.0001 in Level 2"
eventually 30 f1_pings_f2 || fail "f1 does not reach f2's loopback"
echo "ok: f1 pings f2's loopback through isis4r's installed routes"
cli show adjacencies
cli show routes
[ "${KEEP_LAB:-}" ] || down
