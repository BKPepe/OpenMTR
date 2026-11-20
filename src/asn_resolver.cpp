#include "asn_resolver.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#else
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>

// Parsed rather than prefix-matched: the old "172." test threw away the whole
// of 172/8 when only 172.16/12 is private, hiding Google and Cloudflare, and
// it missed 100.64/10 in the other direction.
bool isUnroutableForAsn(const std::string& ip)
{
    in_addr v4{};
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
        // Explicit cast: ntohl() returns u_long on Windows, and the MSVC
        // build compiles with /W4 /WX.
        const uint32_t a = static_cast<uint32_t>(ntohl(v4.s_addr));
        return (a & 0xFF000000u) == 0x0A000000u   // 10/8
            || (a & 0xFFF00000u) == 0xAC100000u   // 172.16/12  (NOT all of 172/8)
            || (a & 0xFFFF0000u) == 0xC0A80000u   // 192.168/16
            || (a & 0xFF000000u) == 0x7F000000u   // 127/8 loopback
            || (a & 0xFFFF0000u) == 0xA9FE0000u   // 169.254/16 link-local
            || (a & 0xFFC00000u) == 0x64400000u   // 100.64/10 CGNAT
            || a == 0u;                           // 0.0.0.0
    }

    in6_addr v6{};
    if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
        const unsigned char* b = reinterpret_cast<const unsigned char*>(&v6);
        if ((b[0] & 0xFE) == 0xFC) return true;                  // fc00::/7 ULA
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;  // fe80::/10 link-local
        for (int i = 0; i < 16; ++i) if (b[i]) return false;
        return true;                                             // ::
    }

    return true;   // not an address we can query for
}

std::string asnQueryName(const std::string& ip, bool ipv6)
{
    char name[128];
    if (!ipv6) {
        in_addr a{};
        if (inet_pton(AF_INET, ip.c_str(), &a) != 1)
            return {};
        const unsigned char* b = reinterpret_cast<const unsigned char*>(&a);
        std::snprintf(name, sizeof(name), "%u.%u.%u.%u.origin.asn.cymru.com",
                      static_cast<unsigned>(b[3]), static_cast<unsigned>(b[2]),
                      static_cast<unsigned>(b[1]), static_cast<unsigned>(b[0]));
        return name;
    }
    in6_addr a{};
    if (inet_pton(AF_INET6, ip.c_str(), &a) != 1)
        return {};
    static const char hex[] = "0123456789abcdef";
    const unsigned char* b = reinterpret_cast<const unsigned char*>(&a);
    std::string q;
    q.reserve(64 + 22);
    for (int i = 15; i >= 0; --i) {
        q += hex[b[i] & 0x0F];
        q += '.';
        q += hex[b[i] >> 4];
        q += '.';
    }
    q += "origin6.asn.cymru.com";
    return q;
}

std::string asnFromTxt(std::string_view txt)
{
    std::string_view field = txt.substr(0, txt.find('|'));
    const char* space = " \t\n\v\f\r";
    const size_t first = field.find_first_not_of(space);
    if (first == std::string_view::npos)
        return {};
    field = field.substr(first, field.find_last_not_of(space) - first + 1);
    if (field == "0")
        return {};
    // Text from DNS that goes into the table and the reports: anything but
    // numbers separated by spaces is dropped rather than passed on.
    for (const char c : field) {
        if ((c < '0' || c > '9') && c != ' ')
            return {};
    }
    return std::string(field);
}

#ifndef _WIN32
std::string asnFromDnsAnswer(const unsigned char* answer, int length)
{
    ns_msg msg;
    if (!answer || length <= 0 || ns_initparse(answer, length, &msg) < 0)
        return {};
    const int count = ns_msg_count(msg, ns_s_an);
    for (int i = 0; i < count; ++i) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
            return {};                        // malformed from here on
        if (ns_rr_type(rr) != ns_t_txt)
            continue;                         // e.g. a CNAME in front
        // TXT RDATA is a sequence of <length byte><bytes> character-strings;
        // Team Cymru sends one.
        const unsigned char* rdata = ns_rr_rdata(rr);
        const unsigned       rdlen = ns_rr_rdlen(rr);
        if (rdlen < 1 || rdata[0] + 1u > rdlen)
            continue;
        return asnFromTxt(std::string_view(reinterpret_cast<const char*>(rdata + 1), rdata[0]));
    }
    return {};
}
#endif

#ifdef _WIN32
// Team Cymru's TXT strings are ASCII; converted as UTF-8 all the same.
static std::string utf8FromWide(const wchar_t* text)
{
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (bytes <= 1)
        return {};
    std::string out(static_cast<size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), bytes, nullptr, nullptr);
    out.resize(static_cast<size_t>(bytes - 1));
    return out;
}
#endif

std::string lookupAsn(const std::string& ip, bool ipv6)
{
    if (ip.empty() || isUnroutableForAsn(ip))
        return {};
    const std::string query = asnQueryName(ip, ipv6);
    if (query.empty())
        return {};

#ifdef _WIN32
    std::wstring wquery;                    // a plain ASCII name: widened byte by byte
    for (const char c : query)
        wquery += static_cast<wchar_t>(static_cast<unsigned char>(c));
    // DnsQuery_W() always fills in wide records. PDNS_RECORD is that type
    // only where UNICODE is defined, which Qt does for the window app and
    // nothing does for a build without it.
    PDNS_RECORDW records = nullptr;
    const DNS_STATUS status = DnsQuery_W(wquery.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD,
                                         nullptr, reinterpret_cast<PDNS_RECORD*>(&records),
                                         nullptr);
    if (status != ERROR_SUCCESS || !records)
        return {};
    std::string result;
    for (PDNS_RECORDW r = records; r; r = r->pNext) {
        if (r->wType == DNS_TYPE_TEXT && r->Data.TXT.dwStringCount > 0) {
            result = asnFromTxt(utf8FromWide(r->Data.TXT.pStringArray[0]));
            break;
        }
    }
    DnsFree(records, DnsFreeRecordList);
    return result;
#else
    // Room for any UDP answer and then some (musl and glibc retry a
    // truncated answer over TCP). A longer answer is cut to this size, which
    // ns_initparse() then rejects; Team Cymru's are about 100 bytes.
    unsigned char answer[4096];
#ifdef __APPLE__
    // macOS's res_query() shares one global resolver state between threads;
    // the res_n* functions take a state of their own. res_ndestroy(), not
    // res_nclose(): on Apple the latter only closes the sockets and leaks
    // the rest of the state.
    struct __res_state state;
    std::memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0)
        return {};
    int length = res_nquery(&state, query.c_str(), ns_c_in, ns_t_txt, answer, sizeof(answer));
    res_ndestroy(&state);
#else
    // glibc keeps its resolver state per thread and musl keeps none, so the
    // plain call is safe from any thread here.
    int length = res_query(query.c_str(), ns_c_in, ns_t_txt, answer, sizeof(answer));
#endif
    if (length < 0)
        return {};
    length = std::min(length, static_cast<int>(sizeof(answer)));
    return asnFromDnsAnswer(answer, length);
#endif
}
