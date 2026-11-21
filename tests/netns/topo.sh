#!/bin/sh
# ==========================================================================
#  tests/netns/topo.sh — a three-hop test network in network namespaces
#
#    client --- r1 --- r2 --- dest          (run as root; Linux only)
#
#    sudo tests/netns/topo.sh up             create it
#    sudo tests/netns/topo.sh exec CMD...    run CMD in the client namespace
#    sudo tests/netns/topo.sh down           remove it
#
#  Tracing 203.0.113.2 from the client answers with exactly three hops:
#  198.51.100.1 (r1), 192.0.2.2 (r2), 203.0.113.2 (dest); with IPv6,
#  2001:db8:3::2 answers via 2001:db8:1::1, 2001:db8:2::2. All addresses are
#  documentation ranges (RFC 5737, RFC 3849), so nothing here can collide
#  with a real network, and nothing leaves the machine.
#
#  The client namespace keeps the kernel's default net.ipv4.ping_group_range
#  ("1 0": no unprivileged ping sockets), so root there exercises the
#  engine's raw-socket fallback; set it in the namespace to test ping
#  sockets instead:
#    sudo tests/netns/topo.sh exec sysctl -w net.ipv4.ping_group_range="0 2147483647"
# ==========================================================================
set -eu

C=omtr-c R1=omtr-r1 R2=omtr-r2 D=omtr-d

have_ipv6() { [ -d /proc/sys/net/ipv6 ]; }

up() {
    for ns in $C $R1 $R2 $D; do
        ip netns add $ns
        ip -n $ns link set lo up
    done
    ip link add c0  netns $C  type veth peer name r1a netns $R1
    ip link add r1b netns $R1 type veth peer name r2a netns $R2
    ip link add r2b netns $R2 type veth peer name d0  netns $D

    addr() {   # namespace, interface, IPv4/prefix, IPv6/prefix
        ip -n "$1" addr add "$3" dev "$2"
        if have_ipv6; then ip -n "$1" addr add "$4" dev "$2" nodad; fi
        ip -n "$1" link set "$2" up
    }
    addr $C  c0  198.51.100.2/24 2001:db8:1::2/64
    addr $R1 r1a 198.51.100.1/24 2001:db8:1::1/64
    addr $R1 r1b 192.0.2.1/24    2001:db8:2::1/64
    addr $R2 r2a 192.0.2.2/24    2001:db8:2::2/64
    addr $R2 r2b 203.0.113.1/24  2001:db8:3::1/64
    addr $D  d0  203.0.113.2/24  2001:db8:3::2/64

    ip -n $C  route add default via 198.51.100.1
    ip -n $R1 route add 203.0.113.0/24 via 192.0.2.2
    ip -n $R2 route add default via 192.0.2.1
    ip -n $D  route add default via 203.0.113.1
    if have_ipv6; then
        ip -n $C  -6 route add default via 2001:db8:1::1
        ip -n $R1 -6 route add 2001:db8:3::/64 via 2001:db8:2::2
        ip -n $R2 -6 route add default via 2001:db8:2::1
        ip -n $D  -6 route add default via 2001:db8:3::1
    fi

    for ns in $R1 $R2 $D; do
        # Routers forward, and nobody rate-limits its ICMP errors: one
        # Time Exceeded per probe, or the test would see random loss.
        ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1
        ip netns exec $ns sysctl -qw net.ipv4.icmp_ratelimit=0
        if have_ipv6; then
            ip netns exec $ns sysctl -qw net.ipv6.conf.all.forwarding=1
            ip netns exec $ns sysctl -qw net.ipv6.icmp.ratelimit=0
        fi
    done
}

down() {
    for ns in $C $R1 $R2 $D; do
        ip netns del $ns 2>/dev/null || true
    done
}

case "${1:-}" in
    up)   up ;;
    down) down ;;
    exec) shift; exec ip netns exec $C "$@" ;;
    *)    echo "usage: $0 up | down | exec CMD..." >&2; exit 2 ;;
esac
