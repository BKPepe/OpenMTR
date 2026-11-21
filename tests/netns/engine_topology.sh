#!/bin/sh
# ==========================================================================
#  tests/netns/engine_topology.sh — the engine across a real three-hop path
#
#    sudo tests/netns/engine_topology.sh build/tests/engine_tests
#
#  Builds tests/netns/topo.sh's network and runs engine_tests' "topology"
#  case in it: through a raw socket (root in a namespace whose
#  ping_group_range refuses ping sockets — the fallback a stock OpenWrt
#  needs) and through a ping socket (Time Exceeded via the IP_RECVERR error
#  queue), for IPv4 and, where the kernel has it, IPv6. Linux only.
# ==========================================================================
set -eu

engine_tests=${1:?usage: $0 path/to/engine_tests}
topo="$(dirname "$0")/topo.sh"

"$topo" down
"$topo" up
trap '"$topo" down' EXIT

run() {
    echo "== $*"
    "$topo" exec "$engine_tests" topology "$@"
}

v4="203.0.113.2 198.51.100.1 192.0.2.2 203.0.113.2"
v6="2001:db8:3::2 2001:db8:1::1 2001:db8:2::2 2001:db8:3::2"

# shellcheck disable=SC2086  # the hop lists are meant to split
{
    "$topo" exec sysctl -qw net.ipv4.ping_group_range="1 0"
    run auto $v4                       # refused ping socket: raw fallback
    run raw  $v4
    if [ -d /proc/sys/net/ipv6 ]; then
        run auto $v6
    fi

    "$topo" exec sysctl -qw net.ipv4.ping_group_range="0 2147483647"
    run ping $v4                       # ping socket, error queue
    if [ -d /proc/sys/net/ipv6 ]; then
        run ping $v6
    fi
}
echo "engine topology: all passed"
