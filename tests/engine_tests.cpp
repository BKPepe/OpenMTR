// ==========================================================================
//  engine_tests.cpp - tests for the tracer engine alone (no Qt, no window).
//  Nothing here sends a packet off the machine.
//  Usage: engine_tests <case>. Exit status 0 = pass.
// ==========================================================================
#include "tracer.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

// MainWindow prints these numbers into the hop tooltip and the export, so on
// POSIX every one of them must stay the Windows SDK's (ipexport.h) value.
static_assert(IP_BUF_TOO_SMALL == 11001 && IP_DEST_NET_UNREACHABLE == 11002
              && IP_DEST_HOST_UNREACHABLE == 11003 && IP_DEST_PROT_UNREACHABLE == 11004
              && IP_DEST_PORT_UNREACHABLE == 11005 && IP_NO_RESOURCES == 11006
              && IP_BAD_OPTION == 11007 && IP_HW_ERROR == 11008
              && IP_PACKET_TOO_BIG == 11009 && IP_REQ_TIMED_OUT == 11010
              && IP_BAD_REQ == 11011 && IP_BAD_ROUTE == 11012
              && IP_TTL_EXPIRED_TRANSIT == 11013 && IP_TTL_EXPIRED_REASSEM == 11014
              && IP_PARAM_PROBLEM == 11015 && IP_SOURCE_QUENCH == 11016
              && IP_OPTION_TOO_BIG == 11017 && IP_BAD_DESTINATION == 11018
              && IP_GENERAL_FAILURE == 11050,
              "IP_* status values must match the Windows SDK");

// An engine destroyed while a reverse-DNS worker it started is still running.
// That is the use-after-free 1.3.0 shipped after the fix for it was lost in
// an upload (0f67645): against that tree this aborts ("mutex lock failed") or
// hangs, which is what the ctest TIMEOUT is for. useDNS = false keeps every
// worker on getnameinfo(NI_NUMERICHOST), so no resolver is involved.
static void dns_lifetime()
{
    for (int i = 0; i < 5000; ++i) {
        OpenMTROptions o;
        o.useDNS = false;
        auto net = std::make_unique<OpenMTRNet>(o);
        net->SetAddr(0, htonl(0x7F000001u + static_cast<unsigned>(i & 0xFF)));
        net.reset();
    }
    // Give the last workers time to find their engine gone before exit.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

static std::string nameOf(OpenMTRNet& n, int hop)
{
    return n.GetHopSnapshot(hop).name;
}

// SetErrorName() only fills an empty name, except that a "Not sent" text is
// provisional: the next status that is not local, or a resolved name,
// replaces it.
static void status_text()
{
    OpenMTROptions o;
    o.useDNS = false;
    OpenMTRNet n(o);
    char resolved[] = "router.example";

    n.SetErrorName(0, OPENMTR_NOT_SENT_NO_ROUTE);
    CHECK(nameOf(n, 0) == "Not sent: no route from this machine.");
    n.SetErrorName(0, OPENMTR_NOT_SENT_REFUSED);           // first local text stays
    CHECK(nameOf(n, 0) == "Not sent: no route from this machine.");
    n.SetErrorName(0, IP_REQ_TIMED_OUT);                   // a real status replaces it
    CHECK(nameOf(n, 0) == "Request timed out.");
    n.SetErrorName(0, OPENMTR_NOT_SENT_NO_ROUTE);          // ...and is not replaced back
    CHECK(nameOf(n, 0) == "Request timed out.");
    n.SetErrorName(0, IP_DEST_HOST_UNREACHABLE);           // first real status stays
    CHECK(nameOf(n, 0) == "Request timed out.");

    n.SetErrorName(1, OPENMTR_NOT_SENT_TOO_BIG);
    n.SetName(1, resolved);                                // a name replaces it
    CHECK(nameOf(n, 1) == "router.example");
    n.SetErrorName(1, OPENMTR_NOT_SENT_OTHER);             // and a name is never replaced
    n.SetErrorName(1, IP_REQ_TIMED_OUT);
    CHECK(nameOf(n, 1) == "router.example");

    const DWORD notSent[] = { OPENMTR_NOT_SENT_NO_ROUTE, OPENMTR_NOT_SENT_NO_ADDRESS,
                              OPENMTR_NOT_SENT_TOO_BIG, OPENMTR_NOT_SENT_NO_BUFFERS,
                              OPENMTR_NOT_SENT_REFUSED, OPENMTR_NOT_SENT_OTHER };
    int hop = 2;
    for (DWORD st : notSent) {
        n.SetErrorName(hop, st);
        CHECK(nameOf(n, hop).rfind("Not sent: ", 0) == 0);
        ++hop;
    }
}

// Whether this process may open an unprivileged ICMP socket of that family
// (on Linux, net.ipv4.ping_group_range decides). Without one, DoTrace()
// returns at once, and a test built on a trace would pass without testing
// anything — so such a test reports itself skipped instead.
static bool pingSocketAvailable(int family)
{
    const int proto = family == AF_INET6 ? static_cast<int>(IPPROTO_ICMPV6)
                                         : static_cast<int>(IPPROTO_ICMP);
    const int fd = ::socket(family, SOCK_DGRAM, proto);
    if (fd < 0)
        return false;
    ::close(fd);
    return true;
}

// An IPv6 trace whose first hop never answers must still find the route's
// length. RecalcMaxLocked() used to decide the family from hop 1's address,
// so until hop 1 answered — forever, if it never does — GetMax() stayed at
// MAX_HOPS. fe80::1 without a scope id makes every sendto() fail locally, so
// no hop ever gets an address and nothing leaves the machine; the
// destination is then marked at hop 4 the way a reply would mark it.
static int v6_silent_first_hop()
{
    if (!pingSocketAvailable(AF_INET6)) {
        std::printf("skipped: no unprivileged ICMPv6 socket here\n");
        return 77;
    }
    OpenMTROptions o;
    o.useDNS = false;
    OpenMTRNet net(o);
    sockaddr_in6 dest{};
#ifdef __APPLE__
    dest.sin6_len = sizeof(dest);
#endif
    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "fe80::1", &dest.sin6_addr);
    std::thread trace([&] { net.DoTrace(reinterpret_cast<sockaddr*>(&dest)); });

    // Wait until DoTrace() is past its setup: hop 1 has had a probe.
    const auto t0 = std::chrono::steady_clock::now();
    while (net.GetHopSnapshot(0).xmit == 0
           && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(3))
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const bool started = net.GetHopSnapshot(0).xmit > 0;
    CHECK(started);            // the socket opens here, so the trace must run

    if (started) {
        IPV6_ADDRESS_EX hop4{};
        std::memcpy(hop4.sin6_addr, &dest.sin6_addr, sizeof(hop4.sin6_addr));
        net.SetAddr6(3, hop4);
        std::printf("GetMax() = %d\n", net.GetMax());
        CHECK(net.GetMax() == 4);
    }
    net.StopTrace();
    trace.join();
    return 0;
}

int main(int argc, char** argv)
{
    const std::string name = argc > 1 ? argv[1] : "";
    int rc = 0;                    // 77 = skipped (see pingSocketAvailable)
    if (name == "dns_lifetime")
        dns_lifetime();
    else if (name == "status_text")
        status_text();
    else if (name == "v6_silent_first_hop")
        rc = v6_silent_first_hop();
    else {
        std::printf("unknown case \"%s\"\n", name.c_str());
        return 2;
    }
    if (g_failures)
        return 1;
    return rc;
}
