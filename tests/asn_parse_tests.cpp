// ==========================================================================
//  asn_parse_tests.cpp — src/asn_resolver.h without a network
//
//  The query names Team Cymru expects, the TXT field parsing, which
//  addresses are never queried, and (POSIX) DNS answer messages built byte
//  by byte here: a plain answer, a CNAME in front, NXDOMAIN, compressed and
//  uncompressed owner names, a lying length byte and a truncated message.
//  Then AsnCache with a stand-in lookup: how long a lookup that never
//  answers counts as pending.
// ==========================================================================

#include "asn_resolver.h"
#include "asncache.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

static void query_names()
{
    CHECK(asnQueryName("8.8.8.8", false) == "8.8.8.8.origin.asn.cymru.com");
    CHECK(asnQueryName("1.2.3.4", false) == "4.3.2.1.origin.asn.cymru.com");
    CHECK(asnQueryName("203.0.113.200", false) == "200.113.0.203.origin.asn.cymru.com");
    CHECK(asnQueryName("2001:db8::1", true) ==
          "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com");
    CHECK(asnQueryName("2a00:1450:4001:82a::200e", true) ==
          "e.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.a.2.8.0.1.0.0.4.0.5.4.1.0.0.a.2.origin6.asn.cymru.com");
    CHECK(asnQueryName("2001:db8::1", false).empty());     // wrong family
    CHECK(asnQueryName("1.2.3.4", true).empty());
    CHECK(asnQueryName("not an address", false).empty());
    CHECK(asnQueryName("", true).empty());
}

static void txt_fields()
{
    CHECK(asnFromTxt("15169 | 8.8.8.0/24 | US | arin | 2023-12-28") == "15169");
    CHECK(asnFromTxt("23028 1234 | 1.2.3.0/24 | US | arin | 2001-01-01") == "23028 1234");
    CHECK(asnFromTxt("  64500\t| x") == "64500");
    CHECK(asnFromTxt("64500") == "64500");                 // no '|' at all
    CHECK(asnFromTxt("0 | 0.0.0.0/8 | ZZ | iana |").empty());   // not announced
    CHECK(asnFromTxt(" | x").empty());
    CHECK(asnFromTxt("").empty());
    // Only numbers and spaces get through: the field is text from DNS.
    CHECK(asnFromTxt("=1+1 | x").empty());
    CHECK(asnFromTxt("AS64500 | x").empty());
    CHECK(asnFromTxt("64500\n=1+1 | x").empty());
    CHECK(asnFromTxt("64500\x1b[31m | x").empty());
    CHECK(asnFromTxt("64500,64501 | x").empty());
}

static void unroutable()
{
    for (const char* ip : { "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
                            "127.0.0.1", "169.254.1.1", "100.64.0.1", "100.127.255.255",
                            "0.0.0.0", "fd00::1", "fc00::1", "fe80::1", "::", "",
                            "garbage", "1.2.3" })
        CHECK(isUnroutableForAsn(ip));
    for (const char* ip : { "8.8.8.8", "172.15.255.255", "172.32.0.1", "100.63.255.255",
                            "100.128.0.1", "203.0.113.5", "2001:db8::1", "2606:4700::1111" })
        CHECK(!isUnroutableForAsn(ip));
}

#ifndef _WIN32
using Bytes = std::vector<unsigned char>;

static void put16(Bytes& b, unsigned v)
{
    b.push_back(static_cast<unsigned char>(v >> 8));
    b.push_back(static_cast<unsigned char>(v & 0xFF));
}

static void putName(Bytes& b, const std::string& name)
{
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        b.push_back(static_cast<unsigned char>(dot - start));
        b.insert(b.end(), name.begin() + static_cast<long>(start), name.begin() + static_cast<long>(dot));
        start = dot + 1;
    }
    b.push_back(0);
}

struct Rr {
    unsigned type;
    Bytes    rdata;
    bool     compressedOwner = true;
};

// A response to a TXT query for `qname` with the given answer records.
static Bytes response(const std::string& qname, const std::vector<Rr>& answers, unsigned rcode = 0)
{
    Bytes b;
    put16(b, 0x1234);                        // id
    put16(b, 0x8180 | rcode);                // QR, RD, RA, rcode
    put16(b, 1);                             // QDCOUNT
    put16(b, static_cast<unsigned>(answers.size()));
    put16(b, 0);
    put16(b, 0);
    putName(b, qname);
    put16(b, 16);                            // QTYPE TXT
    put16(b, 1);                             // QCLASS IN
    for (const Rr& rr : answers) {
        if (rr.compressedOwner) {
            b.push_back(0xC0);               // pointer to the question name
            b.push_back(12);
        } else {
            putName(b, qname);
        }
        put16(b, rr.type);
        put16(b, 1);
        put16(b, 0);                         // TTL
        put16(b, 300);
        put16(b, static_cast<unsigned>(rr.rdata.size()));
        b.insert(b.end(), rr.rdata.begin(), rr.rdata.end());
    }
    return b;
}

static Bytes txt(const std::string& s)
{
    Bytes r;
    r.push_back(static_cast<unsigned char>(s.size()));
    r.insert(r.end(), s.begin(), s.end());
    return r;
}

static std::string parse(const Bytes& b)
{
    return asnFromDnsAnswer(b.data(), static_cast<int>(b.size()));
}

static void dns_answers()
{
    const std::string q = "8.8.8.8.origin.asn.cymru.com";
    const std::string cymru = "15169 | 8.8.8.0/24 | US | arin | 2023-12-28";

    CHECK(parse(response(q, { { 16, txt(cymru) } })) == "15169");
    CHECK(parse(response(q, { { 16, txt(cymru), false } })) == "15169");   // uncompressed owner
    CHECK(parse(response(q, { { 16, txt("23028 1234 | 1.2.3.0/24 | US | arin |") } })) == "23028 1234");
    CHECK(parse(response(q, { { 16, txt("0 | 0.0.0.0/8 | ZZ | iana |") } })).empty());
    // A second character-string in the record is ignored.
    {
        Bytes two = txt(cymru);
        const Bytes more = txt("ignored");
        two.insert(two.end(), more.begin(), more.end());
        CHECK(parse(response(q, { { 16, two } })) == "15169");
    }
    // The first TXT record wins; a CNAME in front is skipped.
    {
        Bytes target;
        putName(target, "alias.example");
        CHECK(parse(response(q, { { 5, target }, { 16, txt("64500 | x") }, { 16, txt("64501 | y") } }))
              == "64500");
    }
    // NXDOMAIN, and an answer without TXT records.
    CHECK(parse(response(q, {}, 3)).empty());
    {
        Bytes a = { 192, 0, 2, 1 };
        CHECK(parse(response(q, { { 1, a } })).empty());
    }
    // A length byte claiming more than the record holds: skipped.
    {
        Bytes lying = txt(cymru);
        lying[0] = 200;
        CHECK(parse(response(q, { { 16, lying } })).empty());
        CHECK(parse(response(q, { { 16, lying }, { 16, txt("64502 | z") } })) == "64502");
        CHECK(parse(response(q, { { 16, Bytes{} } })).empty());          // empty RDATA
    }
    // Truncated anywhere: never a crash, never a value from past the end.
    {
        const Bytes full = response(q, { { 16, txt(cymru) } });
        for (size_t len = 0; len < full.size(); ++len) {
            const Bytes cut(full.begin(), full.begin() + static_cast<long>(len));
            const std::string r = asnFromDnsAnswer(cut.data(), static_cast<int>(cut.size()));
            CHECK(r.empty() || r == "15169");
        }
    }
    CHECK(asnFromDnsAnswer(nullptr, 0).empty());
}
#endif

// A stand-in for lookupAsn(): 198.51.100.1 answers only after 3 s, like a
// resolver that keeps retrying a dead server; 203.0.113.x after 700 ms, like
// a slow one that does answer; anything else at once.
static std::atomic<int> g_lookups{0};
static std::string fakeLookup(const std::string& ip, bool /*ipv6*/)
{
    ++g_lookups;
    if (ip == "198.51.100.1") {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return "64500";
    }
    if (ip.rfind("203.0.113.", 0) == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        return "64511";
    }
    return ip == "192.0.2.1" ? "64501" : "";
}

// Polls `cache.get(ip)` until it is `want` or `timeout` has passed.
static bool waitFor(const AsnCache& cache, const std::string& ip, const char* want,
                    std::chrono::milliseconds timeout)
{
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < end) {
        if (cache.get(ip, false) == want)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
}

static long long msSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
}

// A lookup that never answers stops counting as pending after
// AsnCache::kPendingTimeout, is not started again, and its late answer still
// lands in the cache.
static void cache_pending_timeout()
{
    using namespace std::chrono;
    AsnCache cache(fakeLookup);
    const auto t0 = steady_clock::now();

    CHECK(cache.get("10.1.2.3", false) == "-");          // unroutable: no lookup at all
    CHECK(cache.get("192.0.2.1", false) == "-");
    CHECK(cache.get("198.51.100.1", false) == "-");
    CHECK(waitFor(cache, "192.0.2.1", "64501", milliseconds(1500)));
    // Timing checks only count when this thread got to run in time.
    bool young = cache.hasPending();
    if (msSince(t0) < 1800)
        CHECK(young);                                    // the slow one, under 2 s old

    std::this_thread::sleep_until(t0 + AsnCache::kPendingTimeout + milliseconds(200));
    const bool pendingLater = cache.hasPending();
    if (msSince(t0) < 2900)                              // before the slow answer can land
        CHECK(!pendingLater);
    CHECK(cache.get("198.51.100.1", false) == "-");
    CHECK(waitFor(cache, "198.51.100.1", "64500", milliseconds(4000)));
    CHECK(g_lookups == 2);
}

// Slow lookups that do answer stay pending until they do, however many there
// are (a route has up to 30 hops): all of them start at once, as before, so
// 16 lookups of 700 ms each are answered well inside kPendingTimeout. Run
// them a few at a time and some would drop out of "pending" unanswered.
static void cache_many_slow_lookups()
{
    using namespace std::chrono;
    g_lookups = 0;
    AsnCache cache(fakeLookup);
    const auto t0 = steady_clock::now();
    std::vector<std::string> ips;
    for (int i = 1; i <= 16; ++i)
        ips.push_back("203.0.113." + std::to_string(i));
    for (const std::string& ip : ips)
        CHECK(cache.get(ip, false) == "-");
    while (cache.hasPending() && msSince(t0) < 5000)
        std::this_thread::sleep_for(milliseconds(10));
    const long long settled = msSince(t0);
    int answered = 0;
    for (const std::string& ip : ips)
        answered += cache.get(ip, false) == "64511";
    std::printf("16 slow lookups: no longer pending after %lld ms, %d answered\n", settled, answered);
    CHECK(answered == 16);
    CHECK(g_lookups == 16);
}

int main()
{
    cache_pending_timeout();
    cache_many_slow_lookups();
    query_names();
    txt_fields();
    unroutable();
#ifndef _WIN32
    dns_answers();
#endif
    if (g_failures)
        std::printf("%d check(s) failed\n", g_failures);
    return g_failures ? 1 : 0;
}
