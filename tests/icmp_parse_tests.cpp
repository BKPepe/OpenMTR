// ==========================================================================
//  icmp_parse_tests.cpp — src/icmp_parse.h against hand-made packets
//
//  Every case is a packet as one recvfrom() would return it, built byte by
//  byte here: our own echo replies, ICMP errors quoting our probes, and the
//  look-alikes that must NOT be taken for an answer (someone else's ping,
//  another program's UDP traceroute, truncated or malformed quotes). Ends
//  with random buffers of every length, which must never read out of
//  bounds — run under AddressSanitizer in CI.
// ==========================================================================

#include "icmp_parse.h"

#include <cstdio>
#include <cstdint>
#include <random>
#include <vector>

using namespace icmpparse;

static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

using Bytes = std::vector<uint8_t>;

static void put16(Bytes& b, uint16_t v)
{
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

static Bytes echoHeader(uint8_t type, uint16_t id, uint16_t seq)
{
    Bytes b = { type, 0, 0, 0 };   // type, code, checksum (unchecked)
    put16(b, id);
    put16(b, seq);
    return b;
}

// A minimal IPv4 header (no options unless `ihlWords` > 5) carrying `proto`.
static Bytes ipv4Header(uint8_t proto, int ihlWords = 5, int version = 4)
{
    Bytes b(static_cast<size_t>(ihlWords) * 4, 0);
    b[0] = static_cast<uint8_t>((version << 4) | (ihlWords & 0x0F));
    b[8] = 64;          // TTL
    b[9] = proto;
    return b;
}

static Bytes cat(std::initializer_list<Bytes> parts)
{
    Bytes out;
    for (const Bytes& p : parts)
        out.insert(out.end(), p.begin(), p.end());
    return out;
}

static Match p4(const Bytes& b, bool hasIp, bool filter = false, uint16_t id = 0)
{
    return parseIcmp4(b.data(), b.size(), hasIp, filter, id);
}

static Match p6(const Bytes& b, bool filter = false, uint16_t id = 0)
{
    return parseIcmp6(b.data(), b.size(), filter, id);
}

static void ipv4_cases()
{
    const uint16_t id = 0x1234, seq = (7 << 11) | 42;

    // Echo reply, Linux ping socket (no IP header, id rewritten: no filter).
    {
        const Match m = p4(echoHeader(kEchoReply, 0x9999, seq), false);
        CHECK(m.valid && m.isReply && m.seq == seq && m.type == kEchoReply);
    }
    // Echo reply with the IP header in front (macOS, raw sockets).
    {
        const Bytes b = cat({ ipv4Header(kProtoIcmp), echoHeader(kEchoReply, id, seq) });
        const Match m = p4(b, true, true, id);
        CHECK(m.valid && m.isReply && m.seq == seq);
        CHECK(!p4(b, true, true, id + 1).valid);          // someone else's ping
        const Bytes opt = cat({ ipv4Header(kProtoIcmp, 6), echoHeader(kEchoReply, id, seq) });
        CHECK(p4(opt, true, true, id).valid);             // IP options are skipped
    }
    // Time Exceeded quoting our echo request: answered, from the quote.
    {
        const Bytes quote = cat({ ipv4Header(kProtoIcmp), echoHeader(kEcho, id, seq) });
        const Bytes b = cat({ ipv4Header(kProtoIcmp), echoHeader(kTimeExceeded, 0, 0), quote });
        const Match m = p4(b, true, true, id);
        CHECK(m.valid && !m.isReply && m.type == kTimeExceeded && m.seq == seq);
        CHECK(!p4(b, true, true, id + 1).valid);          // quotes someone else's probe
        const Bytes noIp = cat({ echoHeader(kTimeExceeded, 0, 0), quote });
        CHECK(p4(noIp, false, true, id).valid);
    }
    // Destination Unreachable (code 1, host) quoting our probe.
    {
        Bytes unreach = echoHeader(kDestUnreach, 0, 0);
        unreach[1] = 1;
        const Bytes b = cat({ unreach, ipv4Header(kProtoIcmp), echoHeader(kEcho, id, seq) });
        const Match m = p4(b, false, true, id);
        CHECK(m.valid && m.type == kDestUnreach && m.code == 1 && m.seq == seq);
    }
    // Look-alikes that must be ignored.
    {
        // another program's UDP traceroute: same offsets, protocol 17
        Bytes udp = { 0x82, 0x9A, 0x82, 0x9B, 0, 8, 0, 0 };
        const Bytes b = cat({ echoHeader(kTimeExceeded, 0, 0), ipv4Header(17), udp });
        CHECK(!p4(b, false, false, 0).valid);
        // a quote of an ICMP message that is not an echo request
        const Bytes q2 = cat({ echoHeader(kTimeExceeded, 0, 0), ipv4Header(kProtoIcmp),
                               echoHeader(kEchoReply, id, seq) });
        CHECK(!p4(q2, false, true, id).valid);
        // truncated: the quoted ICMP header is cut short
        Bytes cut = cat({ echoHeader(kTimeExceeded, 0, 0), ipv4Header(kProtoIcmp),
                          echoHeader(kEcho, id, seq) });
        cut.resize(cut.size() - 1);
        CHECK(!p4(cut, false, true, id).valid);
        // bad header lengths and versions
        CHECK(!p4(cat({ ipv4Header(kProtoIcmp, 4), echoHeader(kEchoReply, id, seq) }), true).valid);
        CHECK(!p4(cat({ ipv4Header(kProtoIcmp, 5, 6), echoHeader(kEchoReply, id, seq) }), true).valid);
        CHECK(!p4(cat({ echoHeader(kTimeExceeded, 0, 0), ipv4Header(kProtoIcmp, 3),
                        echoHeader(kEcho, id, seq) }), false).valid);
        CHECK(!p4(cat({ ipv4Header(kProtoIcmp, 15) }), true).valid);   // IHL past the end
        // too short to be anything, and types we never answer to
        CHECK(!p4(Bytes{ kEchoReply, 0, 0 }, false).valid);
        CHECK(!p4(echoHeader(kEcho, id, seq), false).valid);
        CHECK(!p4(echoHeader(5 /* redirect */, id, seq), false).valid);
    }
}

// IPv6 header (40 bytes) with `next` as its Next Header.
static Bytes ipv6Header(uint8_t next)
{
    Bytes b(40, 0);
    b[0] = 0x60;
    b[6] = next;
    b[7] = 64;
    return b;
}

static void ipv6_cases()
{
    const uint16_t id = 0x4321, seq = (12 << 11) | 3;

    {
        const Match m = p6(echoHeader(kV6EchoReply, 0x7777, seq));
        CHECK(m.valid && m.isReply && m.seq == seq);
        CHECK(!p6(echoHeader(kV6EchoReply, 0x7777, seq), true, id).valid);
    }
    // Time Exceeded quoting our echo request.
    {
        const Bytes b = cat({ echoHeader(kV6TimeExceeded, 0, 0), ipv6Header(kProtoIcmpV6),
                              echoHeader(kV6EchoRequest, id, seq) });
        const Match m = p6(b, true, id);
        CHECK(m.valid && !m.isReply && m.type == kV6TimeExceeded && m.seq == seq);
    }
    // Every error type quotes; Packet Too Big and Parameter Problem too.
    for (uint8_t type : { kV6DestUnreach, kV6PacketTooBig, kV6ParamProblem }) {
        const Bytes b = cat({ echoHeader(type, 0, 0), ipv6Header(kProtoIcmpV6),
                              echoHeader(kV6EchoRequest, id, seq) });
        CHECK(p6(b, true, id).valid);
    }
    // Extension headers a middlebox inserted into the quote are walked.
    {
        Bytes hbh = { kV6Fragment, 1, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0 };   // 16 bytes
        Bytes frag = { kProtoIcmpV6, 0, 0, 0, 0, 0, 0, 0 };
        const Bytes b = cat({ echoHeader(kV6TimeExceeded, 0, 0), ipv6Header(kV6HopByHop),
                              hbh, frag, echoHeader(kV6EchoRequest, id, seq) });
        const Match m = p6(b, true, id);
        CHECK(m.valid && m.seq == seq);
    }
    // Look-alikes.
    {
        Bytes udp = { 0x82, 0x9A, 0x82, 0x9B, 0, 8, 0, 0 };
        CHECK(!p6(cat({ echoHeader(kV6TimeExceeded, 0, 0), ipv6Header(17), udp })).valid);
        CHECK(!p6(cat({ echoHeader(kV6TimeExceeded, 0, 0), ipv6Header(50 /* ESP */), udp })).valid);
        CHECK(!p6(cat({ echoHeader(kV6TimeExceeded, 0, 0), ipv6Header(kProtoIcmpV6),
                        echoHeader(kV6EchoReply, id, seq) }), true, id).valid);
        Bytes cut = cat({ echoHeader(kV6TimeExceeded, 0, 0), ipv6Header(kProtoIcmpV6),
                          echoHeader(kV6EchoRequest, id, seq) });
        cut.resize(cut.size() - 1);
        CHECK(!p6(cut, true, id).valid);
        // an extension header claiming more bytes than there are
        Bytes longHbh = { kProtoIcmpV6, 200, 0, 0, 0, 0, 0, 0 };
        CHECK(!p6(cat({ echoHeader(kV6TimeExceeded, 0, 0), ipv6Header(kV6HopByHop), longHbh,
                        echoHeader(kV6EchoRequest, id, seq) }), true, id).valid);
        CHECK(!p6(Bytes{ kV6EchoReply, 0, 0 }).valid);
        CHECK(!p6(echoHeader(kV6EchoRequest, id, seq)).valid);   // our own probe looped back
    }
}

// Random input of every length up to 600 bytes, with and without a valid
// IP header in front: whatever the verdict, no read may leave the buffer
// (each case gets a buffer of exactly its length, so AddressSanitizer
// catches an overread of even one byte).
static void random_input()
{
    std::mt19937 rng(12345);
    for (int round = 0; round < 40; ++round) {
        for (size_t len = 0; len <= 600; ++len) {
            std::vector<uint8_t> buf(len);
            for (auto& b : buf) b = static_cast<uint8_t>(rng());
            if (len > 0 && (round & 1)) buf[0] = 0x45;                 // plausible IPv4 header
            if (len > 28 && (round & 2)) buf[20] = kTimeExceeded;      // an error type
            if (len > 48 && (round & 4)) buf[48] = 0x45;               // plausible quoted header
            (void)parseIcmp4(buf.data(), len, round & 1, round & 8, 0x1234);
            (void)parseIcmp6(buf.data(), len, round & 8, 0x1234);
        }
    }
}

int main()
{
    ipv4_cases();
    ipv6_cases();
    random_input();
    if (g_failures)
        std::printf("%d check(s) failed\n", g_failures);
    return g_failures ? 1 : 0;
}
