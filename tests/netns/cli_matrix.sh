#!/bin/sh
# ==========================================================================
#  tests/netns/cli_matrix.sh — the report mode end to end, in a test network
#
#    sudo tests/netns/cli_matrix.sh path/to/OpenMTR
#
#  Builds tests/netns/topo.sh's three-hop network with fakedns.py answering
#  reverse lookups and Team Cymru ASN queries, and runs `OpenMTR --report`
#  against it: every output format, --output, the exit codes (0, 1, 2, 4,
#  5, 130), Ctrl+C, an unprivileged user with and without ping sockets, and
#  root through the raw-socket fallback. Works with the window app's binary
#  and with a build without Qt alike. Linux only; needs python3.
# ==========================================================================
set -u

bin=${1:?usage: $0 path/to/OpenMTR}
case "$bin" in /*) ;; *) bin="$(pwd)/$bin" ;; esac
here=$(cd "$(dirname "$0")" && pwd)
topo="$here/topo.sh"
tmp=$(mktemp -d)
chmod 755 "$tmp"
failures=0

cleanup() {
    [ -n "${dns_pid:-}" ] && kill "$dns_pid" 2>/dev/null
    "$topo" down
    rm -rf /etc/netns/omtr-c "$tmp"
}
trap cleanup EXIT

"$topo" down
"$topo" up || exit 1
# `ip netns exec` bind-mounts every file of /etc/netns/<ns>/ over its /etc
# namesake: the client asks fakedns.py, running on r1, and asks it directly
# (no NSS module such as systemd-resolved's, which would ask the host's DNS).
mkdir -p /etc/netns/omtr-c
echo "nameserver 198.51.100.1" > /etc/netns/omtr-c/resolv.conf
printf 'passwd: files\ngroup: files\nhosts: files dns\n' > /etc/netns/omtr-c/nsswitch.conf
ip netns exec omtr-r1 python3 -I "$here/fakedns.py" 198.51.100.1 &
dns_pid=$!
sleep 1

check() {   # description, then a shell condition
    if eval "$2"; then
        echo "ok   - $1"
    else
        echo "FAIL - $1"
        failures=$((failures + 1))
    fi
}

run() {     # run OpenMTR in the client namespace; stdout/stderr to files, $rc
    "$topo" exec "$@" > "$tmp/out" 2> "$tmp/err"
    rc=$?
}

# Runs the rest of the command line as uid/gid 65534 (nobody), no groups.
as_nobody="setpriv --reuid=65534 --regid=65534 --clear-groups"

ping_sockets() {   # allow or refuse unprivileged ping sockets in the client namespace
    "$topo" exec sysctl -qw net.ipv4.ping_group_range="$1"
}

# --- root, ping sockets refused: the raw-socket fallback -------------------
ping_sockets "1 0"
run "$bin" --report --time 3 --json 203.0.113.2
check "root, raw socket: exit 0" '[ "$rc" -eq 0 ]'
check "JSON parses" 'python3 -I -m json.tool < "$tmp/out" > /dev/null'
check "the three hops, in order" \
      'python3 -I -c "import json,sys; d=json.load(sys.stdin); sys.exit([h[\"ip\"] for h in d[\"hops\"]] != [\"198.51.100.1\",\"192.0.2.2\",\"203.0.113.2\"])" < "$tmp/out"'
check "host names from the reverse lookups" \
      'python3 -I -c "import json,sys; d=json.load(sys.stdin); sys.exit([h[\"hostname\"] for h in d[\"hops\"]] != [\"r1.test\",\"r2.test\",\"dest.test\"])" < "$tmp/out"'
check "ASNs from the Team Cymru TXT records" \
      'python3 -I -c "import json,sys; d=json.load(sys.stdin); sys.exit([h[\"asn\"] for h in d[\"hops\"]] != [64501,64502,64500])" < "$tmp/out"'

if [ -d /proc/sys/net/ipv6 ]; then
    run "$bin" --report --time 3 -6 --json 2001:db8:3::2
    check "IPv6, raw socket: exit 0" '[ "$rc" -eq 0 ]'
    check "IPv6 hops" \
          'python3 -I -c "import json,sys; d=json.load(sys.stdin); sys.exit([h[\"ip\"] for h in d[\"hops\"]] != [\"2001:db8:1::1\",\"2001:db8:2::2\",\"2001:db8:3::2\"])" < "$tmp/out"'
fi

run "$bin" --report --time 2 203.0.113.2
check "text report: exit 0, the table" '[ "$rc" -eq 0 ] && grep -q "^| *3 | *64500 | dest.test" "$tmp/out"'
run "$bin" --report --time 2 --csv 203.0.113.2
check "CSV report: header and three rows" \
      '[ "$rc" -eq 0 ] && [ "$(wc -l < "$tmp/out")" -eq 4 ] && head -1 "$tmp/out" | grep -q "^Hop,ASN,Hostname,IP,"'
run "$bin" --report --time 2 --output "$tmp/report.json" --json 203.0.113.2
check "--output: exit 0, file written, said so" \
      '[ "$rc" -eq 0 ] && python3 -I -m json.tool < "$tmp/report.json" > /dev/null && grep -q "Report written to" "$tmp/err"'
run "$bin" --report --time 1 --output /nonexistent/dir/report.txt 203.0.113.2
check "--output into a missing directory: exit 5" '[ "$rc" -eq 5 ]'

run "$bin" --report --time 3 203.0.113.99
check "no such host on the last network: exit 1" '[ "$rc" -eq 1 ]'

run "$bin" --report --time 0 203.0.113.2
check "--time 0: exit 2" '[ "$rc" -eq 2 ]'
run "$bin" --report --time 1 no-such-name.invalid
check "unresolvable target: exit 3" '[ "$rc" -eq 3 ]'

# Ctrl+C in the middle of the counting window: exit 130, partial report.
"$topo" exec "$bin" --report --time 60 203.0.113.2 > "$tmp/out" 2> "$tmp/err" &
pid=$!
sleep 8
kill -INT "$pid" 2>/dev/null
wait "$pid"
rc=$?
check "Ctrl+C: exit 130 with the report so far" '[ "$rc" -eq 130 ] && grep -q "dest.test" "$tmp/out"'

# --- an unprivileged user ---------------------------------------------------
run $as_nobody "$bin" --report --time 2 203.0.113.2
check "unprivileged, ping sockets refused: exit 4" '[ "$rc" -eq 4 ]'
check "...saying what to change" 'grep -q "ping_group_range" "$tmp/err"'

ping_sockets "0 2147483647"
run $as_nobody "$bin" --report --time 2 --json 203.0.113.2
check "unprivileged, ping sockets allowed: exit 0" '[ "$rc" -eq 0 ]'
check "...the same three hops" \
      'python3 -I -c "import json,sys; d=json.load(sys.stdin); sys.exit(len(d[\"hops\"]) != 3)" < "$tmp/out"'

echo
if [ "$failures" -ne 0 ]; then
    echo "cli matrix: $failures check(s) failed"
    exit 1
fi
echo "cli matrix: all passed"
