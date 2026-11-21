#!/usr/bin/env python3
# ==========================================================================
#  tests/netns/fakedns.py — the DNS server of the test network (topo.sh)
#
#    python3 -I tests/netns/fakedns.py <listen address>
#
#  Answers over UDP, from fixed tables, the two kinds of query OpenMTR makes:
#  reverse lookups (PTR) of the test network's hops, and Team Cymru ASN
#  lookups (TXT under origin.asn.cymru.com / origin6.asn.cymru.com) for
#  them. Everything else gets NXDOMAIN. Standard library only.
# ==========================================================================
import socket
import struct
import sys


def rev4(ip, suffix):
    return ".".join(reversed(ip.split("."))) + "." + suffix


def rev6(ip, suffix):
    packed = socket.inet_pton(socket.AF_INET6, ip)
    nibbles = "".join("%02x" % b for b in packed)
    return ".".join(reversed(nibbles)) + "." + suffix


HOPS = {
    # address:      (PTR name,    TXT for Team Cymru)
    "198.51.100.1": ("r1.test",   "64501 | 198.51.100.0/24 | ZZ | test | 2026-01-01"),
    "192.0.2.2":    ("r2.test",   "64502 | 192.0.2.0/24 | ZZ | test | 2026-01-01"),
    "203.0.113.2":  ("dest.test", "64500 | 203.0.113.0/24 | ZZ | test | 2026-01-01"),
    "2001:db8:1::1": ("r1.test",   "64511 | 2001:db8:1::/48 | ZZ | test | 2026-01-01"),
    "2001:db8:2::2": ("r2.test",   "64512 | 2001:db8:2::/48 | ZZ | test | 2026-01-01"),
    "2001:db8:3::2": ("dest.test", "64510 | 2001:db8:3::/48 | ZZ | test | 2026-01-01"),
}

PTR = {}
TXT = {}
for ip, (name, txt) in HOPS.items():
    if ":" in ip:
        PTR[rev6(ip, "ip6.arpa")] = name
        TXT[rev6(ip, "origin6.asn.cymru.com")] = txt
    else:
        PTR[rev4(ip, "in-addr.arpa")] = name
        TXT[rev4(ip, "origin.asn.cymru.com")] = txt


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def parse_query(packet):
    qid, flags, qdcount = struct.unpack("!HHH", packet[:6])
    if qdcount != 1:
        return None
    labels, i = [], 12
    while packet[i] != 0:
        length = packet[i]
        labels.append(packet[i + 1:i + 1 + length].decode("ascii", "replace"))
        i += length + 1
    qtype, qclass = struct.unpack("!HH", packet[i + 1:i + 5])
    question = packet[12:i + 5]
    return qid, flags, ".".join(labels).lower(), qtype, question


def answer(packet):
    parsed = parse_query(packet)
    if parsed is None:
        return None
    qid, flags, name, qtype, question = parsed
    rd = flags & 0x0100
    rdata, rtype = None, None
    if qtype == 12 and name in PTR:
        rtype, rdata = 12, encode_name(PTR[name])
    elif qtype == 16 and name in TXT:
        text = TXT[name].encode()
        rtype, rdata = 16, bytes([len(text)]) + text
    if rdata is None:
        rcode = 3 if name not in PTR and name not in TXT else 0   # NXDOMAIN / no data
        header = struct.pack("!HHHHHH", qid, 0x8080 | rd | rcode, 1, 0, 0, 0)
        return header + question
    header = struct.pack("!HHHHHH", qid, 0x8480 | rd, 1, 1, 0, 0)   # authoritative
    rr = b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + rr


def main():
    if len(sys.argv) != 2:
        print("usage: fakedns.py <listen address>", file=sys.stderr)
        return 2
    family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((sys.argv[1], 53))
    while True:
        packet, peer = sock.recvfrom(4096)
        try:
            reply = answer(packet)
        except (IndexError, struct.error, UnicodeError):
            reply = None
        if reply:
            sock.sendto(reply, peer)


if __name__ == "__main__":
    sys.exit(main())
