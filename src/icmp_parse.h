// ==========================================================================
//  icmp_parse.h — matching received ICMP messages to our probes
//
//  The POSIX engine's receive path, as pure functions over a byte buffer:
//  given what one recvfrom() returned on the ICMP socket, decide whether it
//  answers one of this trace's probes and which (by its sequence number).
//  Kept free of sockets, platform headers and engine state so that it can be
//  unit-tested with hand-made packets (tests/icmp_parse_tests.cpp) and
//  fuzzed (tests/fuzz/fuzz_icmp.cpp): on Linux this parses packets from
//  anyone on the network while possibly running as root (raw-socket mode),
//  so every read is bounds-checked and done byte by byte (no casts of the
//  buffer to header structs, hence no alignment requirement either).
//
//  What arrives on the socket, per mode (see tracer.cpp):
//    - Linux ping socket: echo replies only, without an IP header (ICMP
//      errors go to the socket's error queue instead, handled separately).
//    - macOS/BSD ping socket: every inbound ICMP message, IPv4 ones with
//      their IP header in front.
//    - Linux raw socket: every inbound ICMP message (narrowed by the kernel
//      filter set in tracer.cpp), IPv4 ones with their IP header in front.
//  IPv6 sockets never deliver the IPv6 header.
// ==========================================================================

#pragma once

#include <cstddef>
#include <cstdint>

namespace icmpparse {

// ICMP / ICMPv6 type numbers and IPv6 next-header values used below (RFC 792,
// RFC 4443, RFC 8200). Spelled out here instead of taken from the platform
// headers, whose names differ between systems.
inline constexpr uint8_t kEchoReply      = 0;
inline constexpr uint8_t kDestUnreach    = 3;
inline constexpr uint8_t kEcho           = 8;
inline constexpr uint8_t kTimeExceeded   = 11;

inline constexpr uint8_t kV6DestUnreach  = 1;
inline constexpr uint8_t kV6PacketTooBig = 2;
inline constexpr uint8_t kV6TimeExceeded = 3;
inline constexpr uint8_t kV6ParamProblem = 4;
inline constexpr uint8_t kV6EchoRequest  = 128;
inline constexpr uint8_t kV6EchoReply    = 129;

inline constexpr uint8_t kProtoIcmp      = 1;
inline constexpr uint8_t kV6HopByHop     = 0;
inline constexpr uint8_t kV6Routing      = 43;
inline constexpr uint8_t kV6Fragment     = 44;
inline constexpr uint8_t kProtoIcmpV6    = 58;
inline constexpr uint8_t kV6DestOptions  = 60;

// Echo header: type, code, checksum, identifier, sequence number.
inline constexpr size_t kEchoHeaderLen   = 8;
inline constexpr size_t kIpv4MinHeader   = 20;
inline constexpr size_t kIpv6HeaderLen   = 40;

struct Match {
    bool     valid   = false;   // answers one of our probes; `seq` says which
    bool     isReply = false;   // an echo reply (else an error quoting our probe)
    uint8_t  type    = 0;       // ICMP(v6) type and code of the message received
    uint8_t  code    = 0;
    uint16_t seq     = 0;       // sequence number of the probe it answers
};

inline uint16_t readBe16(const uint8_t* p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// Length of a well-formed IPv4 header at `p` (`len` bytes available), or 0.
inline size_t ipv4HeaderLength(const uint8_t* p, size_t len)
{
    if (len < kIpv4MinHeader || (p[0] >> 4) != 4)
        return 0;
    const size_t ihl = static_cast<size_t>(p[0] & 0x0F) * 4;
    return (ihl >= kIpv4MinHeader && ihl <= len) ? ihl : 0;
}

// An ICMPv4 message: `buf`/`len` as read from the socket, `hasIpHeader` when
// the IPv4 header comes first (macOS ping sockets, Linux raw sockets).
// `filterId` checks the echo identifier against `echoId`: needed wherever
// the socket sees other programs' ICMP traffic too (macOS, raw sockets);
// Linux ping sockets rewrite the identifier and already deliver only their
// own traffic, so the one we sent never appears there.
inline Match parseIcmp4(const uint8_t* buf, size_t len, bool hasIpHeader,
                        bool filterId, uint16_t echoId)
{
    Match m;
    size_t off = 0;
    if (hasIpHeader) {
        off = ipv4HeaderLength(buf, len);
        if (off == 0)
            return m;
    }
    // A complete echo header is 8 bytes; requiring more (a full
    // `struct icmp` is 28) would drop legitimately short ICMP messages.
    if (len - off < kEchoHeaderLen)
        return m;
    const uint8_t* icmp = buf + off;
    const size_t   icmpLen = len - off;
    m.type = icmp[0];
    m.code = icmp[1];

    if (m.type == kEchoReply) {
        if (filterId && readBe16(icmp + 4) != echoId)
            return m;                         // someone else's ping
        m.seq     = readBe16(icmp + 6);
        m.isReply = true;
        m.valid   = true;
        return m;
    }
    if (m.type != kTimeExceeded && m.type != kDestUnreach)
        return m;

    // An ICMP error quotes the IP header and the first 8 bytes of the packet
    // that caused it, starting 8 bytes in. Ours only if that packet was an
    // ICMP echo request, which is where the probe's identifier and sequence
    // number come from — not, say, a UDP datagram of another program's
    // traceroute whose port numbers sit at the same offsets.
    const uint8_t* inner    = icmp + kEchoHeaderLen;
    const size_t   innerLen = icmpLen - kEchoHeaderLen;
    const size_t   innerIp  = ipv4HeaderLength(inner, innerLen);
    if (innerIp == 0 || innerLen < innerIp + kEchoHeaderLen)
        return m;
    if (inner[9] != kProtoIcmp)
        return m;                             // quotes something other than ICMP
    const uint8_t* probe = inner + innerIp;
    if (probe[0] != kEcho)
        return m;                             // quotes an ICMP message that is no probe
    if (filterId && readBe16(probe + 4) != echoId)
        return m;                             // quotes someone else's probe
    m.seq   = readBe16(probe + 6);
    m.valid = true;
    return m;
}

// The ICMPv6 header of the probe an ICMPv6 error quotes: the error's own
// 8-byte header, then the original IPv6 header, then any extension headers
// before the original ICMPv6 header. We never send extension headers
// ourselves, but tunnels and middleboxes can insert them into the quoted
// copy — a fixed +40 offset would then read garbage where the echo header
// was expected. nullptr when the quote is too short, carries an extension
// we cannot walk, or holds no ICMPv6 header.
inline const uint8_t* quotedIcmp6(const uint8_t* buf, size_t len)
{
    size_t off = kEchoHeaderLen;
    if (len < off + kIpv6HeaderLen)
        return nullptr;
    uint8_t next = buf[off + 6];              // the IPv6 header's Next Header
    off += kIpv6HeaderLen;
    while (next != kProtoIcmpV6) {
        // An extension header is at least 8 bytes; its first byte is the
        // next header's type, the second its length in 8-byte units
        // beyond the first 8 (the Fragment header has a fixed size).
        if (off + 8 > len)
            return nullptr;
        switch (next) {
        case kV6HopByHop:
        case kV6Routing:
        case kV6DestOptions:
            next = buf[off];
            off += (static_cast<size_t>(buf[off + 1]) + 1) * 8;
            break;
        case kV6Fragment:
            next = buf[off];
            off += 8;
            break;
        default:
            return nullptr;                   // ESP/unknown — nothing we sent
        }
    }
    if (off + kEchoHeaderLen > len)
        return nullptr;
    return buf + off;
}

// An ICMPv6 message as read from the socket (never with an IPv6 header).
// `filterId`/`echoId` as for parseIcmp4().
inline Match parseIcmp6(const uint8_t* buf, size_t len, bool filterId, uint16_t echoId)
{
    Match m;
    if (len < kEchoHeaderLen)
        return m;
    m.type = buf[0];
    m.code = buf[1];

    if (m.type == kV6EchoReply) {
        if (filterId && readBe16(buf + 4) != echoId)
            return m;
        m.seq     = readBe16(buf + 6);
        m.isReply = true;
        m.valid   = true;
        return m;
    }
    // Every ICMPv6 error quotes the packet that caused it, so one branch
    // matches them all. Packet Too Big and Parameter Problem used to be
    // ignored outright, which surfaced as a plain timeout.
    if (m.type != kV6TimeExceeded && m.type != kV6DestUnreach &&
        m.type != kV6PacketTooBig && m.type != kV6ParamProblem)
        return m;
    const uint8_t* probe = quotedIcmp6(buf, len);
    if (!probe || probe[0] != kV6EchoRequest)
        return m;
    if (filterId && readBe16(probe + 4) != echoId)
        return m;
    m.seq   = readBe16(probe + 6);
    m.valid = true;
    return m;
}

}  // namespace icmpparse
