// ==========================================================================
//  tracer.cpp — implementation of the ICMP traceroute engine
//
//  A single async dispatch loop drives ICMP probes for every TTL (no thread
//  per hop); per-hop statistics are stored in OpenMTRNet's hop table and
//  read back through locked accessors. A small DNS worker resolves each
//  hop's host name in the background. See the comment above DoTrace() for
//  the dispatch design.
// ==========================================================================

// ==========================================================================
//  Includes & macros
// ==========================================================================

#include "tracer.h"
#include "icmp_parse.h"
#include <cstring>

#ifdef _WIN32
#include <process.h>
#else
#include <cerrno>
#include <chrono>
#include <system_error>

// Windows CRT helpers used throughout this file, backed by their POSIX
// equivalents.
inline int strcpy_s(char* dest, size_t destsz, const char* src)
{
    if (!dest || destsz == 0 || !src) return -1;
    size_t len = strlen(src);
    if (len >= destsz) {
        dest[0] = '\0';
        return -1;
    }
    memcpy(dest, src, len + 1);
    return 0;
}

inline ULONGLONG GetTickCount64()
{
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}
#endif

// Tell the IP stack not to fragment our probe packets.
#define IPFLAG_DONT_FRAGMENT 0x02

// ==========================================================================
//  Async dispatch state & forward declarations
// ==========================================================================

struct DnsResolverArgs {
    // Shared ownership, not a raw OpenMTRNet* — the engine can be destroyed
    // while this worker is still blocked in getnameinfo(). See DnsSink.
    std::shared_ptr<DnsSink> sink;
    int                      index;
};

// DNS resolution still runs on its own short-lived worker thread (unrelated
// to probe scheduling). Declared here so the Set* mutators can launch it.
static void DnsResolverThread(void* p);

#ifndef _WIN32
// Translate an ICMPv6 error into the IP_* status the rest of the engine and
// the UI already speak (SetErrorName turns these into the strings shown in
// the Hostname column). Every v6 error used to collapse into
// "Destination host unreachable", which hid the two that actually tell you
// something: Packet Too Big means the path MTU is smaller than the probe —
// nothing to do with reachability — and the unreachable codes distinguish a
// missing route from an administrative block.
//
// RFC 4443 numbering: type 1 = Destination Unreachable (code 0 no route,
// 1 administratively prohibited, 2 beyond scope, 3 address unreachable,
// 4 port unreachable), type 2 = Packet Too Big (a type of its own, not a
// code under type 1), type 4 = Parameter Problem.
static DWORD Icmp6StatusFor(uint8_t type, uint8_t code)
{
    switch (type) {
    case ICMP6_PACKET_TOO_BIG:
        return IP_PACKET_TOO_BIG;
    case ICMP6_PARAM_PROB:
        return IP_PARAM_PROBLEM;
    case ICMP6_DST_UNREACH:
        switch (code) {
        case ICMP6_DST_UNREACH_NOROUTE:     return IP_DEST_NET_UNREACHABLE;
        case ICMP6_DST_UNREACH_ADMIN:       return IP_BAD_ROUTE;
        case ICMP6_DST_UNREACH_BEYONDSCOPE: return IP_DEST_NET_UNREACHABLE;
        case ICMP6_DST_UNREACH_ADDR:        return IP_DEST_HOST_UNREACHABLE;
        case ICMP6_DST_UNREACH_NOPORT:      return IP_DEST_PORT_UNREACHABLE;
        default:                            return IP_DEST_HOST_UNREACHABLE;
        }
    default:
        return IP_GENERAL_FAILURE;
    }
}

// The IPv4 counterpart of Icmp6StatusFor(). Both receive paths use it — the
// recvfrom() one and Linux's error queue — which used to carry a copy each
// and had drifted apart (only the error-queue copy knew "fragmentation
// needed"). RFC 792 numbering: type 3 = Destination Unreachable, code 0 net,
// 2 protocol, 3 port, 4 fragmentation needed and DF set. Anything else falls
// back to host unreachable, as both copies did.
static DWORD Icmp4StatusFor(uint8_t type, uint8_t code)
{
    if (type != ICMP_UNREACH)
        return IP_DEST_HOST_UNREACHABLE;
    switch (code) {
    case ICMP_UNREACH_NET:      return IP_DEST_NET_UNREACHABLE;
    case ICMP_UNREACH_PROTOCOL: return IP_DEST_PROT_UNREACHABLE;
    case ICMP_UNREACH_PORT:     return IP_DEST_PORT_UNREACHABLE;
    case ICMP_UNREACH_NEEDFRAG: return IP_PACKET_TOO_BIG;
    default:                    return IP_DEST_HOST_UNREACHABLE;
    }
}

// Translate a local send failure's errno into one of OpenMTR's "Not sent"
// codes, so a trace that never left the machine says so — and says why —
// instead of "General failure." on every row, and without borrowing the
// wording a router uses for its own ICMP errors.
static DWORD SendStatusFor(int err)
{
    switch (err) {
    case EHOSTUNREACH:      // the common IPv6-is-down case
    case ENETUNREACH:
    case ENETDOWN:          // the interface went away mid-trace
    case EHOSTDOWN:         // on-link next hop did not answer ARP/NDP
        return OPENMTR_NOT_SENT_NO_ROUTE;
    case EADDRNOTAVAIL:     // no usable source address of that family
        return OPENMTR_NOT_SENT_NO_ADDRESS;
    case EMSGSIZE:          // probe exceeds the socket/interface limit
        return OPENMTR_NOT_SENT_TOO_BIG;
    case ENOBUFS:
    case ENOMEM:
        return OPENMTR_NOT_SENT_NO_BUFFERS;
    case EACCES:
    case EPERM:             // e.g. a local packet-filter rule
        return OPENMTR_NOT_SENT_REFUSED;
    default:
        return OPENMTR_NOT_SENT_OTHER;
    }
}
#endif


// ==========================================================================
//  Construction & teardown
// ==========================================================================

// Open the capability handles (IPv4 always; IPv6 if the OS provides it) and
// clear the hop table. Failing to get the v4 handle leaves `initialized`
// false; surfacing that to the user is the caller's job — the engine has no
// UI dependency.
OpenMTRNet::OpenMTRNet(const OpenMTROptions& options)
    : opts(options)
{
    memset(m_hops, 0, sizeof(m_hops));
    memset(&last_remote_addr6, 0, sizeof(last_remote_addr6));

    // Publish ourselves to the reverse-DNS workers; ~OpenMTRNet takes it back.
    m_dnsSink->net = this;

#ifdef _WIN32
    hICMP = IcmpCreateFile();
    if (hICMP == INVALID_HANDLE_VALUE)
        return;

    hICMP6  = Icmp6CreateFile();
    hasIPv6 = (hICMP6 != INVALID_HANDLE_VALUE);

    // Manual-reset: once StopTrace() signals it, it stays signaled for every
    // WaitForMultipleObjects call in the dispatch loop until the next trace
    // resets it, so a stop request can never race a wait that started just
    // before SetEvent() was called.
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!m_stopEvent)
        return;
#else
    // No persistent ICMP handle on POSIX: each trace opens its own ICMP
    // socket instead (see PrepareSocket()). Just probe whether the OS will
    // hand out an IPv6 one, the way PrepareSocket() would try it.
    int testSock = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
#ifdef __linux__
    if (testSock < 0 && (errno == EACCES || errno == EPERM))
        testSock = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
#endif
    if (testSock >= 0) {
        hasIPv6 = true;
        ::close(testSock);
    }
    hICMP  = 0;
    hICMP6 = 0;

    // Self-pipe: wakes the poll() in DoTrace() the moment StopTrace() writes
    // to it, the POSIX equivalent of signalling m_stopEvent on Windows.
    if (pipe(m_stopPipe) < 0) {
        m_stopPipe[0] = -1;
        m_stopPipe[1] = -1;
        return;
    }
    // Non-blocking matters on the read end: DoTrace() drains stale wake-ups
    // with a read() loop that runs before any data exists, so a blocking
    // pipe would park the trace there forever instead of starting it.
    if (fcntl(m_stopPipe[0], F_SETFL, O_NONBLOCK) < 0) {
        ::close(m_stopPipe[0]);
        ::close(m_stopPipe[1]);
        m_stopPipe[0] = -1;
        m_stopPipe[1] = -1;
        return;                       // leaves initialized false
    }
#endif

    initialized = true;
}

// Close whatever ICMP handles we opened.
OpenMTRNet::~OpenMTRNet()
{
    // Cut the reverse-DNS workers loose before anything else is torn down:
    // past this point a worker finding a null `net` drops its result instead
    // of writing into freed memory. Blocks only for an in-flight
    // GetAddr()/SetName() call, never for the resolver itself.
    {
        std::lock_guard<std::mutex> lock(m_dnsSink->mutex);
        m_dnsSink->net = nullptr;
    }

#ifdef _WIN32
    if (initialized) {
        if (hasIPv6 && hICMP6 != INVALID_HANDLE_VALUE)
            IcmpCloseHandle(hICMP6);
        if (hICMP != INVALID_HANDLE_VALUE)
            IcmpCloseHandle(hICMP);
    }
    if (m_stopEvent)
        CloseHandle(m_stopEvent);
#else
    if (m_stopPipe[0] != -1) {
        ::close(m_stopPipe[0]);
        m_stopPipe[0] = -1;
    }
    if (m_stopPipe[1] != -1) {
        ::close(m_stopPipe[1]);
        m_stopPipe[1] = -1;
    }
    // Prepared by PrepareSocket() but never taken over by a DoTrace().
    if (m_fd != -1) {
        ::close(m_fd);
        m_fd = -1;
    }
#endif
}

#ifdef _WIN32
int OpenMTRNet::PrepareSocket(int /*family*/)
{
    return 0;   // the ICMP handles were opened by the constructor
}

std::string OpenMTRSocketErrorText(int /*err*/, int family)
{
    // Not reached: PrepareSocket() cannot fail on Windows.
    return family == AF_INET6 ? "Cannot open an ICMPv6 handle." : "Cannot open an ICMP handle.";
}
#else
int OpenMTRNet::PrepareSocket(int family)
{
    if (m_fd != -1) {
        ::close(m_fd);
        m_fd       = -1;
        m_fdFamily = AF_UNSPEC;
        m_fdRaw    = false;
    }

    const bool isV6  = (family == AF_INET6);
    const int  proto = isV6 ? static_cast<int>(IPPROTO_ICMPV6) : static_cast<int>(IPPROTO_ICMP);
    const auto mode  = opts.socketMode;

    // An unprivileged ping socket first: it needs no privileges where the
    // system allows it (macOS always; Linux for the groups in
    // net.ipv4.ping_group_range).
    int  fd  = -1;
    int  err = 0;
    bool raw = false;
    if (mode != OpenMTROptions::SocketMode::RawOnly) {
        fd = ::socket(family, SOCK_DGRAM, proto);
        if (fd < 0)
            err = errno;
    }
#ifdef __linux__
    // Refused: fall back to a raw ICMP socket, which root (or anything with
    // CAP_NET_RAW) may always open — the two kinds of socket mtr-packet uses
    // too (it tries raw first, as it starts privileged), and what busybox
    // ping (raw only) relies on. This is what makes the engine
    // work on a stock OpenWrt router, which runs everything as root and
    // keeps the kernel's "1 0" ping_group_range. Raw sockets see every ICMP
    // message the host receives, so DoTrace() then filters by echo id and
    // checks quoted packets (see icmp_parse.h), and a kernel filter below
    // drops all but the three types it handles.
    if (fd < 0 && (mode == OpenMTROptions::SocketMode::RawOnly ||
                   (mode == OpenMTROptions::SocketMode::Auto && (err == EACCES || err == EPERM)))) {
        fd = ::socket(family, SOCK_RAW, proto);
        if (fd >= 0)
            raw = true;
        else if (mode == OpenMTROptions::SocketMode::RawOnly)
            err = errno;
        // Auto: report the ping socket's error, not the raw one's — it is
        // the one a user without root can do something about.
    }
#else
    if (mode == OpenMTROptions::SocketMode::RawOnly)
        err = EPROTONOSUPPORT;    // raw mode is implemented for Linux only
#endif
    if (fd < 0)
        return err != 0 ? err : EIO;

    // Non-blocking is a hard requirement: the dispatch loop drains the
    // socket until EAGAIN, which on a blocking socket would park the whole
    // trace on the last recvfrom().
    if (::fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        const int err = errno;
        ::close(fd);
        return err != 0 ? err : EIO;
    }

#ifdef __APPLE__
    // Room for the largest reply. macOS gives an ICMP socket an 8 KB receive
    // buffer (net.inet.raw.recvspace = 8192), and an echo reply to a probe
    // of about 8133 bytes or more does not fit in it with its overhead, so
    // the kernel dropped it and every probe at those ping sizes timed out.
    // A refusal is not fatal: everything else works as before.
    int rcvbuf = 64 * 1024;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
#endif

#ifdef __linux__
    // Linux ping sockets don't hand ICMP error messages (Time Exceeded,
    // Destination Unreachable) to a plain recvfrom() the way macOS/BSD's
    // do — those get delivered to the socket's error queue instead, which
    // has to be explicitly enabled and drained separately. See the
    // POLLERR handling in DoTrace(). (No effect / not needed on macOS or BSD.)
    //
    // Failure here is fatal rather than ignorable: without the error queue
    // no intermediate hop is ever heard from, so every row but the
    // destination would read as a timeout and the app would look like a
    // plain ping pretending to be a traceroute. Better to stop with the
    // engine's own error path than to draw a confidently wrong route.
    //
    // A raw socket needs none of this: it receives the ICMP errors with
    // recvfrom() like any other ICMP message.
    if (!raw) {
        int recverr = 1;
        const int recverrRc = isV6
            ? ::setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &recverr, sizeof(recverr))
            : ::setsockopt(fd, IPPROTO_IP,   IP_RECVERR,   &recverr, sizeof(recverr));
        if (recverrRc < 0) {
            const int setErr = errno;
            ::close(fd);
            return setErr != 0 ? setErr : EIO;
        }
    } else if (isV6) {
        // Kernel-side filter: only the ICMPv6 types the receive path handles
        // reach the socket. A refusal is not fatal — the parser checks
        // everything anyway; the filter only saves the work.
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
        ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
        ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG, &filter);
        ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filter);
        ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &filter);
        (void)::setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    } else {
        // The IPv4 equivalent, ICMP_FILTER from <linux/icmp.h> (a set bit
        // drops that type). Spelled out rather than included: that header
        // clashes with <netinet/ip_icmp.h>.
        constexpr int kSolRaw     = 255;   // SOL_RAW
        constexpr int kIcmpFilter = 1;     // ICMP_FILTER
        const uint32_t filter = ~((1u << icmpparse::kEchoReply) | (1u << icmpparse::kDestUnreach) |
                                  (1u << icmpparse::kTimeExceeded));
        (void)::setsockopt(fd, kSolRaw, kIcmpFilter, &filter, sizeof(filter));
    }
#endif

    m_fd       = fd;
    m_fdFamily = family;
    m_fdRaw    = raw;
    return 0;
}

std::string OpenMTRSocketErrorText(int err, int family)
{
    std::string text = (family == AF_INET6) ? "Cannot open an ICMPv6 socket: "
                                            : "Cannot open an ICMP socket: ";
    text += std::strerror(err);
    text += '.';
    if (err == EAFNOSUPPORT && family == AF_INET6)
        text += " IPv6 is not available on this system.";
#ifdef __linux__
    // Linux allows unprivileged ICMP ("ping") sockets only to the groups in
    // net.ipv4.ping_group_range (it covers ICMPv6 too). The kernel default,
    // "1 0", allows nobody, not even root; many distributions widen it, but
    // not all of them do, and containers and OpenWrt keep the default.
    // When PrepareSocket() reports this, the raw-socket fallback has been
    // tried as well and failed for want of privileges.
    if (err == EACCES || err == EPERM)
        text += " Unprivileged ping sockets are not allowed for this user's group by"
                " net.ipv4.ping_group_range, and raw ICMP sockets need root (CAP_NET_RAW)."
                " Allow ping sockets with: sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"";
#endif
    return text;
}
#endif

// Zero the entire hop table so a fresh trace starts from clean statistics.
void OpenMTRNet::ResetHops()
{
    // Under m_mutex like every other write to m_hops: a reader (the UI's
    // refresh, or a test) may already be taking snapshots when a trace
    // starts on its worker thread.
    std::lock_guard<std::mutex> lock(m_mutex);
    memset(m_hops, 0, sizeof(m_hops));
    m_lastAlive.store(0, std::memory_order_relaxed);
    m_parkingEnabled.store(false, std::memory_order_relaxed);
    m_maxHops.store(MAX_HOPS, std::memory_order_relaxed);
}

// Restart statistics from this moment: zero every hop's counters and RTT
// figures while keeping addresses and resolved names, and enable parking of
// probes far beyond the route edge. Called by the UI when the results table
// is revealed, so Loss/Sent/Recv and Best/Avrg/Wrst/Last/Jttr all describe
// the same measurement window instead of mixing in warm-up probes.
void OpenMTRNet::ResetStats()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& h : m_hops) {
        h.xmit      = 0;
        h.returned  = 0;
        h.total     = 0;
        h.jitterSum = 0;
        h.anomalyCount  = 0;
        h.anomalyLast   = 0;
        h.last      = 0;
        h.best      = 0;
        h.worst     = 0;
    }
    m_parkingEnabled.store(true, std::memory_order_relaxed);
}

// ==========================================================================
//  Trace control & async dispatch
// ==========================================================================
//
// DoTrace() drives all MAX_HOPS probes from a single dispatch loop rather
// than one blocking OS thread per TTL. It runs on whichever thread called
// DoTrace() (the wrapper's background thread). Each hop gets its own
// ICMP handle (still one per hop — see the rationale in HopState below) and
// its own Event handle; IcmpSendEcho2()/Icmp6SendEcho2() is submitted with
// that event instead of blocking, and the dispatcher sleeps in
// WaitForMultipleObjects() on every outstanding hop's event plus a stop
// event, waking only when a reply/timeout completes or the next hop's
// scheduled send falls due — never busy-polling, and never holding a
// thread's stack and kernel scheduling slot per TTL.
//
// This relies on documented IP Helper API behaviour: passing a non-NULL
// Event makes the call return immediately (GetLastError() == ERROR_IO_PENDING)
// and signals that event, with the ReplyBuffer already filled in (Status
// included), once a reply arrives or the request times out — the same way the
// Windows SDK's own IcmpSendEcho2 samples use the Event parameter. On a
// timeout the reply buffer's Status reads IP_REQ_TIMED_OUT.

// Per-hop async probe state, owned entirely by the dispatch loop in
// DoTrace() — never touched from another thread, so it needs no locking of
// its own (only the calls into OpenMTRNet's locked accessors/mutators do).
struct HopState {
    int    ttl          = 0;      // 1-based TTL this state probes
    bool   pending       = false; // an IcmpSendEcho2 call is outstanding
    bool   retired       = false; // past the route edge; no longer probed
    HANDLE hIcmp         = INVALID_HANDLE_VALUE;
    HANDLE hEvent        = nullptr;
    IPINFO ipOptions{};
    std::vector<unsigned char> requestData;
    std::vector<unsigned char> replyBuffer;
    // Absolute per-hop schedule: next send is due at t0 + slot*period. t0
    // carries this hop's initial stagger (see the comment in DoTrace());
    // period is intervalMs, shared by every hop. Sends sleep to an absolute
    // target time, evaluated by the dispatcher rather than by each hop on its
    // own stack.
    ULONGLONG t0            = 0;
    ULONGLONG slot          = 0;
    ULONGLONG lastProbeTick = 0;
};

// Start a trace: drive all MAX_HOPS probes from one dispatch loop instead of
// one thread per TTL (see the design note above). Picks the v4 or v6 path
// from the destination's address family.
#ifdef _WIN32
void OpenMTRNet::DoTrace(sockaddr* dest)
{
    ResetHops();
    if (m_stopEvent) ResetEvent(m_stopEvent);
    // Set `tracing` first, then look for a stop. StopTrace() does the same
    // two steps the other way round (stopRequested, then tracing = false),
    // so whichever side runs first, the trace ends: either we see the
    // request here, or its `tracing = false` lands after ours. A stop that
    // arrived before the ResetEvent() above is caught here too.
    tracing = true;
    if (stopRequested) {
        tracing = false;
        return;
    }

    const bool isV6       = (dest->sa_family == AF_INET6);
    const WORD payloadLen = (WORD)opts.pingsize;

    // Period is the configured interval plus a small fixed offset. ICMP
    // error rate limiters commonly refill on a whole-second cycle; probing
    // at exactly that period would pin every arrival to one fixed phase of
    // the limiter's clock, and a hop parked at the token-refill boundary
    // would drop replies rhythmically. The extra 16 ms sweeps the arrival
    // phase across the limiter's whole cycle once per ~64 probes. Every hop
    // shares the same period, so inter-hop spacing is unaffected.
    ULONGLONG intervalMs = (ULONGLONG)(opts.interval * 1000);
    if (intervalMs == 0) intervalMs = 1000;
    intervalMs += 16;
    const ULONGLONG globalT0 = GetTickCount64();

    IPAddr       destAddr4 = 0;
    sockaddr_in6 destAddr6 = {};
    static const sockaddr_in6 srcAny = { AF_INET6, 0, 0, in6addr_any, 0 };

    m_isV6 = isV6;
    {
        // Under m_mutex like ResetHops() just above: the UI may already be
        // taking snapshots of the hop table.
        std::lock_guard<std::mutex> lock(m_mutex);
        if (isV6)
            m_hops[0].addr6.sin6_family = AF_INET6;
        else
            m_hops[0].addr.sin_family = AF_INET;
    }
    if (isV6) {
        last_remote_addr6 = ((sockaddr_in6*)dest)->sin6_addr;
        destAddr6 = *(sockaddr_in6*)dest;
    } else {
        last_remote_addr = ((sockaddr_in*)dest)->sin_addr;
        destAddr4 = ((sockaddr_in*)dest)->sin_addr.s_addr;
    }

    const size_t replyBufSize =
        (sizeof(ICMP_ECHO_REPLY) > sizeof(ICMPV6_ECHO_REPLY)
            ? sizeof(ICMP_ECHO_REPLY) : sizeof(ICMPV6_ECHO_REPLY)) + 8192;

    std::vector<HopState> hops(MAX_HOPS);
    for (int i = 0; i < MAX_HOPS; ++i) {
        HopState& hs = hops[i];
        hs.ttl = i + 1;

        // Each hop owns a private ICMP handle: a dedicated handle gives the
        // hop's probes a unique ICMP echo identifier on the wire, so stateful
        // devices along the path (which track ICMP flows by that identifier)
        // and Windows itself never have two hops' outstanding requests
        // sharing state.
        hs.hIcmp = isV6 ? Icmp6CreateFile() : IcmpCreateFile();
        if (hs.hIcmp == INVALID_HANDLE_VALUE) { hs.retired = true; continue; }

        hs.hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!hs.hEvent) {
            IcmpCloseHandle(hs.hIcmp);
            hs.hIcmp   = INVALID_HANDLE_VALUE;
            hs.retired = true;
            continue;
        }

        hs.requestData.assign(8192, ' ');
        hs.replyBuffer.assign(replyBufSize, 0);
        hs.ipOptions.Ttl   = (UCHAR)hs.ttl;
        hs.ipOptions.Flags = IPFLAG_DONT_FRAGMENT;

        // Initial per-TTL stagger: hop i's schedule starts 50 ms after hop
        // i-1's, so the hops' probes spread across the interval rather than
        // all firing on the same tick.
        hs.t0   = globalT0 + (ULONGLONG)(hs.ttl - 1) * 50;
        hs.slot = 0;
    }

    // Records one completed probe's outcome, whether the completion arrived
    // via the hop's event or (rarely) the call finished inline. Because the
    // call is dispatched asynchronously, the reply buffer's Status field is
    // the only source of truth (there is no live return value to inspect
    // once the event fires) — see the design note above.
    auto complete = [&](HopState& hs) {
        unsigned long status;
        int           rtt;
        if (isV6) {
            auto* r = reinterpret_cast<ICMPV6_ECHO_REPLY*>(hs.replyBuffer.data());
            status = r->Status;
            rtt    = (int)r->RoundTripTime;
            if (status == IP_SUCCESS || status == IP_TTL_EXPIRED_TRANSIT) {
                RecordProbe(hs.ttl - 1, true, rtt);
                SetAddr6(hs.ttl - 1, r->Address);
            }
        } else {
            auto* r = reinterpret_cast<ICMP_ECHO_REPLY*>(hs.replyBuffer.data());
            status = r->Status;
            rtt    = (int)r->RoundTripTime;
            if (status == IP_SUCCESS || status == IP_TTL_EXPIRED_TRANSIT) {
                RecordProbe(hs.ttl - 1, true, rtt);
                SetAddr(hs.ttl - 1, r->Address);
            }
        }
        if (status != IP_SUCCESS && status != IP_TTL_EXPIRED_TRANSIT) {
            SetErrorName(hs.ttl - 1, status);
            // A plain timeout carries no anomaly (RecordProbe's contract);
            // any other status is a genuine anomaly to surface.
            RecordProbe(hs.ttl - 1, false, 0, status == IP_REQ_TIMED_OUT ? 0ul : status);
        }
        hs.pending = false;
        // Advance to the next slot strictly in the future: a reply lands
        // within the hop's slot (next = slot + 1); a full timeout skips the
        // slots it consumed and resumes on schedule, so the hop's phase
        // survives timeouts/parking unchanged.
        hs.slot = (GetTickCount64() - hs.t0) / intervalMs + 1;
    };

    // Submits hop `hs`'s next probe. Async dispatch (the common case) just
    // marks it pending and returns; the dispatch loop below waits for its
    // event. A hard failure at submission time (not a network timeout — the
    // call itself couldn't be started) is recorded as an anomaly right away.
    auto submit = [&](HopState& hs) {
        DWORD ret = isV6
            ? Icmp6SendEcho2(hs.hIcmp, hs.hEvent, nullptr, nullptr,
                              const_cast<sockaddr_in6*>(&srcAny), &destAddr6,
                              hs.requestData.data(), payloadLen,
                              &hs.ipOptions, hs.replyBuffer.data(), (DWORD)hs.replyBuffer.size(),
                              ECHO_REPLY_TIMEOUT)
            : IcmpSendEcho2(hs.hIcmp, hs.hEvent, nullptr, nullptr,
                             destAddr4, hs.requestData.data(), payloadLen,
                             &hs.ipOptions, hs.replyBuffer.data(), (DWORD)hs.replyBuffer.size(),
                             ECHO_REPLY_TIMEOUT);
        hs.lastProbeTick = GetTickCount64();

        if (ret != 0) {
            complete(hs); // finished inline (e.g. loopback) — no event wait
            return;
        }
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            hs.pending = true;
        } else {
            SetErrorName(hs.ttl - 1, err);
            RecordProbe(hs.ttl - 1, false, 0, err);
            hs.slot = (GetTickCount64() - hs.t0) / intervalMs + 1;
        }
    };

    auto retire = [&](HopState& hs) {
        if (hs.hEvent) { CloseHandle(hs.hEvent); hs.hEvent = nullptr; }
        if (hs.hIcmp != INVALID_HANDLE_VALUE) { IcmpCloseHandle(hs.hIcmp); hs.hIcmp = INVALID_HANDLE_VALUE; }
        hs.retired = true;
    };

    // Next scheduled send time for a hop that isn't pending/retired: its
    // normal slot, or — once parking kicks in for a hop stuck well past the
    // route's known edge (UNKNOWN_HOP_MARGIN) — the end of its patrol window
    // (UNKNOWN_PATROL_MS), so probes that would only die unanswered stop
    // spamming rate-limited routers and get sent just occasionally instead.
    auto nextDue = [&](const HopState& hs) -> ULONGLONG {
        if (IsParkingEnabled() && hs.lastProbeTick != 0 &&
            hs.ttl > GetLastAlive() + UNKNOWN_HOP_MARGIN) {
            return hs.lastProbeTick + UNKNOWN_PATROL_MS;
        }
        return hs.t0 + hs.slot * intervalMs;
    };

    bool anyActive = true;
    while (tracing && anyActive) {
        anyActive = false;
        const ULONGLONG now = GetTickCount64();

        // 1) Submit every hop whose send slot has arrived.
        for (auto& hs : hops) {
            if (hs.retired) continue;
            if (hs.pending) { anyActive = true; continue; }

            if (hs.ttl > GetMax()) { retire(hs); continue; }
            anyActive = true;

            if (now >= nextDue(hs)) submit(hs);
        }

        if (!anyActive || !tracing) break;

        // 2) Wait for whichever comes first: a hop's reply/timeout event,
        //    the stop event, or the next hop's scheduled send time.
        HANDLE handles[MAX_HOPS + 1];
        int    handleHop[MAX_HOPS + 1];
        int    count = 0;
        handles[count] = m_stopEvent; handleHop[count] = -1; ++count;
        for (auto& hs : hops) {
            if (hs.pending) { handles[count] = hs.hEvent; handleHop[count] = hs.ttl - 1; ++count; }
        }

        ULONGLONG soonest = GetTickCount64() + 250;
        for (auto& hs : hops) {
            if (hs.retired || hs.pending) continue;
            ULONGLONG due = nextDue(hs);
            if (due < soonest) soonest = due;
        }
        const ULONGLONG nowWait = GetTickCount64();
        const ULONGLONG rest    = (soonest > nowWait) ? (soonest - nowWait) : 0;
        const DWORD     timeoutMs = (DWORD)(rest < 250 ? rest : 250);

        DWORD w = WaitForMultipleObjects(count, handles, FALSE, timeoutMs);
        if (!tracing) break;
        if (w == WAIT_TIMEOUT || w == WAIT_FAILED) continue;

        int idx = (int)(w - WAIT_OBJECT_0);
        if (idx <= 0 || idx >= count) continue; // stop event, or spurious
        int hopIndex = handleHop[idx];
        if (hopIndex >= 0) complete(hops[hopIndex]);
    }

    for (auto& hs : hops) retire(hs);
    tracing = false;
}
#else
// Internet checksum (RFC 1071) over an ICMPv4 packet — the kernel doesn't
// compute this for us on a raw/dgram ICMP socket the way it does for TCP/UDP.
// The result goes into the packet with memcpy(), on either byte order: the
// 16-bit words are summed as they lie in memory, and an odd last byte is the
// first byte of a word padded with zero. (Added as a plain number it is the
// low byte, which is only right on a little-endian CPU.)
uint16_t OpenMTRIcmpChecksum(const unsigned char* data, size_t length)
{
    uint32_t sum = 0;
    for (; length > 1; data += 2, length -= 2) {
        uint16_t word;
        std::memcpy(&word, data, sizeof(word));
        sum += word;
    }
    if (length == 1) {
        uint16_t word = 0;
        std::memcpy(&word, data, 1);
        sum += word;
    }
    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);
    return static_cast<uint16_t>(~sum);
}

// POSIX counterpart of the Windows dispatch loop above: same per-hop
// scheduling and parking logic, but built on unprivileged ping sockets
// (SOCK_DGRAM/IPPROTO_ICMP[V6], no root needed on Linux or macOS) and
// poll() instead of IcmpSendEcho2()/WaitForMultipleObjects().
void OpenMTRNet::DoTrace(sockaddr* dest)
{
    ResetHops();

    // Drain any stale wake-ups left over from a previous trace.
    if (m_stopPipe[0] != -1) {
        char dummy[128];
        while (::read(m_stopPipe[0], dummy, sizeof(dummy)) > 0) {}
    }

    // Same order as the Windows DoTrace() above, and for the same reason: a
    // stop whose wake-up byte the drain just ate is still seen here.
    tracing = true;
    if (stopRequested) {
        tracing = false;
        return;
    }

    const bool isV6      = (dest->sa_family == AF_INET6);
    const int  payloadLen = static_cast<int>(opts.pingsize);

    // Echo id stamped into every outgoing probe of this trace.
    const uint16_t echoId = static_cast<uint16_t>(getpid() & 0xFFFF);
#ifdef __APPLE__
    // macOS (like the BSDs) delivers a copy of every inbound ICMP message to
    // every open ICMP dgram socket — there is no per-socket demultiplexing
    // by echo id the way Linux ping sockets do it. The sequence number alone
    // is deterministic ((hop << 11) | probe count), so two concurrent traces (a
    // second OpenMTR, ping, mtr …) collide on it and record each other's
    // packets: a silent hop inherits a fabricated address from a foreign
    // reply, and a foreign packet clearing `pending` early makes the real
    // reply arrive "unmatched" — phantom loss. macOS also transmits our id
    // unrewritten, so the id we sent is the id that comes back (in the outer
    // header of echo replies, in the quoted original packet of Time
    // Exceeded / Unreachable) — filter on it.
    const bool filterEchoIdDgram = true;
#else
    // Linux rewrites the outgoing id to the socket's kernel-assigned "port"
    // and already delivers only matching traffic to this socket, so the id
    // we sent never appears on the wire and needs no checking here.
    const bool filterEchoIdDgram = false;
#endif
#ifdef __APPLE__
    // Some BSD kernels (macOS included) hand an ICMP dgram socket each IPv4
    // message with its IP header still in front; Linux ping sockets don't.
    const bool stripIpv4HeaderDgram = true;
#else
    const bool stripIpv4HeaderDgram = false;
#endif

    ULONGLONG intervalMs = static_cast<ULONGLONG>(opts.interval * 1000);
    if (intervalMs == 0)
        intervalMs = 1000;
    // See the Windows-side comment above for why 16 ms is added.
    intervalMs += 16;
    const ULONGLONG globalT0 = GetTickCount64();

    sockaddr_in  destAddr4 = {};
    sockaddr_in6 destAddr6 = {};

    m_isV6 = isV6;
    if (isV6) {
        last_remote_addr6 = (reinterpret_cast<sockaddr_in6*>(dest))->sin6_addr;
        destAddr6 = *reinterpret_cast<sockaddr_in6*>(dest);
    } else {
        last_remote_addr = (reinterpret_cast<sockaddr_in*>(dest))->sin_addr;
        destAddr4 = *reinterpret_cast<sockaddr_in*>(dest);
    }

    // The socket normally comes from PrepareSocket(), called on the caller's
    // thread before this one started (see OpenMTRNetWrapper::DoTrace()), so
    // a refusal has already been reported there. Prepare one here when
    // nobody did, or when it was prepared for the other address family.
    const int family = isV6 ? AF_INET6 : AF_INET;
    if (m_fd < 0 || m_fdFamily != family) {
        if (PrepareSocket(family) != 0) {
            tracing = false;
            return;
        }
    }
    const int  fd      = m_fd;     // this trace owns it from here on, and closes it
    const bool rawMode = m_fdRaw;
    m_fd       = -1;
    m_fdFamily = AF_UNSPEC;
    m_fdRaw    = false;

    // A raw socket (Linux, see PrepareSocket()) sees every ICMP message the
    // host receives, IPv4 ones with their IP header, and our echo id goes
    // out unrewritten — like a macOS ping socket, so the same two flags.
    // ICMP errors arrive through recvfrom() then, not the error queue.
    const bool filterEchoId    = rawMode || filterEchoIdDgram;
    const bool stripIpv4Header = rawMode || stripIpv4HeaderDgram;
#ifdef __linux__
    const bool useErrQueue     = !rawMode;
#else
    const bool useErrQueue     = false;
#endif

    // Per-hop schedule state — the POSIX equivalent of HopState above
    // (no OS-level wait handle, so nothing corresponding to hEvent).
    struct PosixHopState {
        int       ttl           = 0;
        bool      pending       = false;
        bool      retired       = false;
        ULONGLONG t0            = 0;
        ULONGLONG slot          = 0;
        ULONGLONG seq           = 0;
        ULONGLONG lastProbeTick = 0;
        uint16_t  sentSeq       = 0;
        ULONGLONG sentTime      = 0;
    };

    std::vector<PosixHopState> hops(MAX_HOPS);
    for (int i = 0; i < MAX_HOPS; ++i) {
        PosixHopState& hs = hops[i];
        hs.ttl  = i + 1;
        hs.t0   = globalT0 + static_cast<ULONGLONG>(i) * 50;
        hs.slot = 0;
    }

    // Ends a hop's probe, whatever became of it, with the same resync as the
    // Windows complete() lambda: skip the slots a gap consumed so the hop
    // resumes on schedule instead of firing the backlog at RTT speed. Every
    // path that clears `pending` goes through here, send failures included —
    // one that did not would leave nextDue() in the past and the loop would
    // spin. A hop is only finished after submit(), which never runs before
    // its t0, so the subtraction cannot wrap.
    auto finish = [&](PosixHopState& hs) {
        hs.pending = false;
        hs.slot = (GetTickCount64() - hs.t0) / intervalMs + 1;
    };

    // A probe that never left the machine: say why, count it, finish it.
    auto failSend = [&](PosixHopState& hs, int err) {
        const DWORD st = SendStatusFor(err);
        SetErrorName(hs.ttl - 1, st);
        RecordProbe(hs.ttl - 1, false, 0, st);
        finish(hs);
    };

    // sendto() for a probe. On Linux a ping socket with IP_RECVERR also keeps
    // the last ICMP error it queued in sk_err — a router's Time Exceeded
    // included — and the next send returns that error instead of sending
    // (sock_alloc_send_pskb() in net/core/sock.c). A failed send there can
    // therefore be a router's answer to an earlier probe rather than a
    // problem on this machine, and it would be reported as "Not sent". The
    // failed call has cleared sk_err, so one immediate retry tells the two
    // apart: a real local failure fails again, and the router's entry stays
    // in the error queue for the drain below.
    auto sendProbe = [&](const std::vector<unsigned char>& pkt,
                         const sockaddr* to, socklen_t toLen) -> ssize_t {
        ssize_t sent = ::sendto(fd, pkt.data(), pkt.size(), 0, to, toLen);
#ifdef __linux__
        if (sent < 0)
            sent = ::sendto(fd, pkt.data(), pkt.size(), 0, to, toLen);
#endif
        return sent;
    };

    // Send one probe for a hop. The sequence number packs the hop index into
    // its top five bits so a reply can be matched back to its hop without
    // any extra per-hop state travelling over the wire (see the reply
    // parsing below). Five bits, not a whole byte: MAX_HOPS only needs five,
    // and the eleven bits left for the per-hop probe counter push its
    // wrap-around from 256 probes (~4 min at the 1 s interval — a reply
    // delayed past that could match a fresh probe of the same hop) out to
    // 2048 (~34 min).
    static_assert(MAX_HOPS <= 32, "hop index must fit the top 5 bits of icmp_seq");
    auto submit = [&](PosixHopState& hs) {
        hs.seq++;
        uint16_t seq  = static_cast<uint16_t>(((hs.ttl - 1) << 11) | (hs.seq & 0x7FF));
        hs.sentSeq    = seq;
        hs.sentTime   = GetTickCount64();
        hs.lastProbeTick = hs.sentTime;
        hs.pending    = true;

        if (isV6) {
            int val = hs.ttl;
            // A failed hop-limit set would send this probe with the previous
            // hop's TTL, so the reply would be filed against the wrong row.
            // Count it as a failed probe instead of quietly mismeasuring.
            if (::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val)) < 0) {
                failSend(hs, errno);
                return;
            }

            struct icmp6_hdr req6 = {};
            req6.icmp6_type  = ICMP6_ECHO_REQUEST;
            req6.icmp6_code  = 0;
            req6.icmp6_id    = htons(echoId);
            req6.icmp6_seq   = htons(seq);
            req6.icmp6_cksum = 0;

            std::vector<unsigned char> pkt(sizeof(struct icmp6_hdr) + payloadLen, ' ');
            std::memcpy(pkt.data(), &req6, sizeof(struct icmp6_hdr));

            const ssize_t sent = sendProbe(pkt, reinterpret_cast<sockaddr*>(&destAddr6), sizeof(sockaddr_in6));
            if (sent < 0) {
                failSend(hs, errno);
            }
        } else {
            int val = hs.ttl;
            // Same reasoning as the v6 hop limit above.
            if (::setsockopt(fd, IPPROTO_IP, IP_TTL, &val, sizeof(val)) < 0) {
                failSend(hs, errno);
                return;
            }

            struct icmp req4 = {};
            req4.icmp_type  = ICMP_ECHO;
            req4.icmp_code  = 0;
            req4.icmp_id    = htons(echoId);
            req4.icmp_seq   = htons(seq);
            req4.icmp_cksum = 0;

            // ICMP_MINLEN (8: type, code, checksum, id, seq), NOT
            // sizeof(struct icmp) — that struct embeds a whole struct ip in
            // its union and is 28 bytes, which used to pad every v4 probe
            // with 20 extra bytes (so v4 and v6 measured with different
            // packet sizes than the one configured).
            std::vector<unsigned char> pkt(ICMP_MINLEN + payloadLen, ' ');
            std::memcpy(pkt.data(), &req4, ICMP_MINLEN);

            uint16_t cksum = OpenMTRIcmpChecksum(pkt.data(), pkt.size());
            std::memcpy(pkt.data() + 2, &cksum, sizeof(cksum));

            const ssize_t sent = sendProbe(pkt, reinterpret_cast<sockaddr*>(&destAddr4), sizeof(sockaddr_in));
            if (sent < 0) {
                failSend(hs, errno);
            }
        }
    };

    // Same parking rule as the Windows side: a hop well past the farthest
    // responder is polled rarely instead of every interval.
    auto nextDue = [&](const PosixHopState& hs) -> ULONGLONG {
        if (IsParkingEnabled() && hs.lastProbeTick != 0 &&
            hs.ttl > GetLastAlive() + UNKNOWN_HOP_MARGIN) {
            return hs.lastProbeTick + UNKNOWN_PATROL_MS;
        }
        return hs.t0 + hs.slot * intervalMs;
    };

    bool anyActive = true;
    char readBuf[2048];

    while (tracing && anyActive) {
        anyActive = false;
        ULONGLONG now = GetTickCount64();

        for (auto& hs : hops) {
            if (hs.retired)
                continue;
            if (hs.pending) {
                if (now > hs.sentTime + ECHO_REPLY_TIMEOUT) {
                    finish(hs);
                    // Mirrors the Windows dispatch loop's complete() lambda,
                    // which calls this for IP_REQ_TIMED_OUT too (see above) -
                    // this was the one call missing here, which is why a
                    // hop that never replies at all showed a bare "-"
                    // instead of "Request timed out." on Linux/macOS.
                    // Safe to call unconditionally: SetErrorName() only
                    // writes when the hop's name is still empty (or holds a
                    // provisional "Not sent" text), and the
                    // instant this hop ever gets a real reply, SetAddr()/
                    // SetAddr6() below trigger the one-time DNS resolve
                    // that overwrites it - so an occasional timeout on an
                    // otherwise-responding hop can never leave this text
                    // stuck over its real hostname.
                    SetErrorName(hs.ttl - 1, IP_REQ_TIMED_OUT);
                    RecordProbe(hs.ttl - 1, false, 0);
                } else {
                    anyActive = true;
                    continue;
                }
            }
            if (hs.ttl > GetMax()) {
                hs.retired = true;
                continue;
            }
            anyActive = true;
            if (now >= nextDue(hs))
                submit(hs);
        }

        if (!anyActive || !tracing)
            break;

        // Wait for either a reply, the next hop's due time, or the stop pipe
        // — whichever comes first.
        struct pollfd fds[2] = {};
        fds[0].fd     = m_stopPipe[0];
        fds[0].events = POLLIN;
        fds[1].fd     = fd;
        fds[1].events = POLLIN | POLLERR;

        ULONGLONG soonest = GetTickCount64() + 250;
        for (auto& hs : hops) {
            if (hs.retired || hs.pending)
                continue;
            ULONGLONG due = nextDue(hs);
            if (due < soonest)
                soonest = due;
        }
        const ULONGLONG nowWait  = GetTickCount64();
        const ULONGLONG rest     = (soonest > nowWait) ? (soonest - nowWait) : 0;
        int timeoutMs = static_cast<int>(rest < 250 ? rest : 250);

        int p = ::poll(fds, 2, timeoutMs);
        if (!tracing)
            break;
        if (p < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (fds[0].revents & POLLIN) {
            char dummy;
            ssize_t discard = ::read(m_stopPipe[0], &dummy, 1);
            (void)discard;
            break;
        }

        // Without an error queue (macOS/BSD, and Linux raw sockets) poll()
        // can still flag POLLERR (e.g. an asynchronous ENETUNREACH on the
        // socket). Only the error-queue block below ever reads it; here the
        // condition would persist and poll() would keep returning
        // immediately — a busy loop pinning a core. Clear the pending error
        // and move on.
        if (!useErrQueue && (fds[1].revents & POLLERR) && !(fds[1].revents & POLLIN)) {
            int soerr = 0;
            socklen_t slen = sizeof(soerr);
            ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
        }

        if (fds[1].revents & POLLIN) {
            while (true) {
                sockaddr_storage from = {};
                socklen_t fromlen = sizeof(from);
                const ssize_t n = ::recvfrom(fd, readBuf, sizeof(readBuf), 0,
                                             reinterpret_cast<sockaddr*>(&from), &fromlen);
                if (n < 0)
                    break;          // EAGAIN/EWOULDBLOCK: drained; anything else: give up for now

                // Which probe (if any) this answers: see icmp_parse.h.
                const uint8_t* pkt = reinterpret_cast<const uint8_t*>(readBuf);
                const icmpparse::Match m = isV6
                    ? icmpparse::parseIcmp6(pkt, static_cast<size_t>(n), filterEchoId, echoId)
                    : icmpparse::parseIcmp4(pkt, static_cast<size_t>(n), stripIpv4Header, filterEchoId, echoId);
                if (!m.valid || from.ss_family != (isV6 ? AF_INET6 : AF_INET))
                    continue;   // not ours — must not clear another hop's pending probe

                const int hopIndex = m.seq >> 11;
                if (hopIndex >= MAX_HOPS)
                    continue;
                PosixHopState& hs = hops[hopIndex];
                if (!hs.pending || hs.sentSeq != m.seq)
                    continue;   // late reply to an earlier probe of this hop

                const ULONGLONG nowRecv = GetTickCount64();
                int rtt = static_cast<int>(nowRecv - hs.sentTime);
                if (rtt <= 0) rtt = 1;
                finish(hs);

                // An echo reply (the destination) or Time Exceeded (a hop on
                // the way) counts as an answer from the sender's address; any
                // other error is that hop's status.
                const bool answered = m.isReply ||
                    m.type == (isV6 ? icmpparse::kV6TimeExceeded : icmpparse::kTimeExceeded);
                if (!answered) {
                    const DWORD errStatus = isV6 ? Icmp6StatusFor(m.type, m.code)
                                                 : Icmp4StatusFor(m.type, m.code);
                    SetErrorName(hopIndex, errStatus);
                    RecordProbe(hopIndex, false, 0, errStatus);
                    continue;
                }
                RecordProbe(hopIndex, true, rtt);
                if (isV6) {
                    const sockaddr_in6* from_in6 = reinterpret_cast<const sockaddr_in6*>(&from);
                    IPV6_ADDRESS_EX addrex = {};
                    addrex.sin6_port     = from_in6->sin6_port;
                    addrex.sin6_flowinfo = from_in6->sin6_flowinfo;
                    addrex.sin6_scope_id = from_in6->sin6_scope_id;
                    std::memcpy(addrex.sin6_addr, &from_in6->sin6_addr, 16);
                    SetAddr6(hopIndex, addrex);
                } else {
                    SetAddr(hopIndex, reinterpret_cast<const sockaddr_in*>(&from)->sin_addr.s_addr);
                }
            }
        }

#ifdef __linux__
        // Linux-only: drain the error queue. As explained by the comment
        // where IP_RECVERR/IPV6_RECVERR get enabled above, this — not the
        // ordinary recvfrom() above — is how Time Exceeded and
        // Destination Unreachable actually arrive on a Linux ping socket.
        // Without this block every intermediate hop just silently "times
        // out" and only the final Echo Reply (via recvfrom) is ever seen,
        // which looks exactly like a plain ping instead of a traceroute.
        if (useErrQueue && (fds[1].revents & POLLERR)) {
            while (true) {
                // Aligned for what is read out of them: CMSG_FIRSTHDR() hands
                // back `ctrl` as a struct cmsghdr, and the quoted probe in
                // `errBuf` is read through struct icmp. A plain char array
                // has no such alignment, which strict-alignment CPUs (MIPS,
                // as in many routers) trap on or emulate slowly.
                alignas(8) unsigned char errBuf[512];
                alignas(struct cmsghdr) char ctrl[512];
                sockaddr_storage from = {};
                struct iovec iov = { errBuf, sizeof(errBuf) };
                struct msghdr msg = {};
                msg.msg_name       = &from;
                msg.msg_namelen    = sizeof(from);
                msg.msg_iov        = &iov;
                msg.msg_iovlen     = 1;
                msg.msg_control    = ctrl;
                msg.msg_controllen = sizeof(ctrl);

                int n = ::recvmsg(fd, &msg, MSG_ERRQUEUE);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    break;
                }

                struct sock_extended_err* ee = nullptr;
                sockaddr* offender = nullptr;
                for (struct cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
                    if ((!isV6 && cm->cmsg_level == IPPROTO_IP   && cm->cmsg_type == IP_RECVERR) ||
                        ( isV6 && cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_RECVERR)) {
                        ee = reinterpret_cast<struct sock_extended_err*>(CMSG_DATA(cm));
                        offender = reinterpret_cast<sockaddr*>(SO_EE_OFFENDER(ee));
                        break;
                    }
                }
                if (!ee)
                    continue;

                // The error queue hands back the ICMP header of our own
                // original outgoing echo request (the one that triggered
                // this error) as the message payload — that's where the
                // matching sequence number comes from, same idea as the
                // embedded-original-packet parsing above.
                uint16_t seq = 0;
                bool haveSeq = false;
                if (!isV6 && n >= ICMP_MINLEN) {
                    haveSeq = true;
                    seq = ntohs((reinterpret_cast<struct icmp*>(errBuf))->icmp_seq);
                } else if (isV6 && n >= static_cast<int>(sizeof(struct icmp6_hdr))) {
                    haveSeq = true;
                    seq = ntohs((reinterpret_cast<struct icmp6_hdr*>(errBuf))->icmp6_seq);
                }
                // An entry the kernel made itself (SO_EE_ORIGIN_LOCAL, from
                // ip_local_error() or ipv6_local_error()) carries no payload,
                // so it ends here too. Nothing is lost: such an error also
                // fails the sendto() that caused it, which recorded it.
                if (!haveSeq)
                    continue;

                int hopIndex = seq >> 11;
                if (hopIndex < 0 || hopIndex >= MAX_HOPS)
                    continue;
                PosixHopState& hs = hops[hopIndex];
                if (!hs.pending || hs.sentSeq != seq)
                    continue;

                const ULONGLONG nowRecv = GetTickCount64();
                int rtt = static_cast<int>(nowRecv - hs.sentTime);
                if (rtt <= 0) rtt = 1;
                finish(hs);

                const bool isTimeExceeded = isV6 ? (ee->ee_type == ICMP6_TIME_EXCEEDED)
                                                  : (ee->ee_type == ICMP_TIMXCEED);
                if (isTimeExceeded) {
                    RecordProbe(hopIndex, true, rtt);
                    if (offender) {
                        if (isV6) {
                            sockaddr_in6* o6 = reinterpret_cast<sockaddr_in6*>(offender);
                            IPV6_ADDRESS_EX addrex = {};
                            addrex.sin6_port     = o6->sin6_port;
                            addrex.sin6_flowinfo = o6->sin6_flowinfo;
                            addrex.sin6_scope_id = o6->sin6_scope_id;
                            std::memcpy(addrex.sin6_addr, &o6->sin6_addr, 16);
                            SetAddr6(hopIndex, addrex);
                        } else {
                            SetAddr(hopIndex, (reinterpret_cast<sockaddr_in*>(offender))->sin_addr.s_addr);
                        }
                    }
                } else {
                    // The error queue reports the same ICMP type/code the
                    // packet carried, so both families map exactly as they
                    // do on the recvfrom path above.
                    const DWORD errStatus = isV6 ? Icmp6StatusFor(ee->ee_type, ee->ee_code)
                                                 : Icmp4StatusFor(ee->ee_type, ee->ee_code);
                    SetErrorName(hopIndex, errStatus);
                    RecordProbe(hopIndex, false, 0, errStatus);
                }
            }
        }
#endif
    }

    if (fd >= 0)
        ::close(fd);
    tracing = false;
}
#endif

// Signal the dispatch loop to stop: flip the flag it polls every pass, and
// wake it immediately from WaitForMultipleObjects() rather than making it
// wait out its current timeout slice.
void OpenMTRNet::StopTrace()
{
    stopRequested = true;     // before `tracing` — see DoTrace()
    tracing = false;
#ifdef _WIN32
    if (m_stopEvent) SetEvent(m_stopEvent);
#else
    if (m_stopPipe[1] != -1) {
        char dummy = 1;
        ssize_t discard = ::write(m_stopPipe[1], &dummy, 1);
        (void)discard;
    }
#endif
}

// Resolve one hop's address to a host name: numeric form first, then a
// reverse-DNS name if DNS lookups are enabled.
static void DnsResolverThread(void* p)
{
    std::unique_ptr<DnsResolverArgs> args(static_cast<DnsResolverArgs*>(p));
    DnsSink& sink = *args->sink;
    char hostname[NI_MAXHOST];

    // Read everything needed for the lookup in one locked step, then let go
    // of the sink: the engine must stay destructible while getnameinfo()
    // blocks, which on a hop with no PTR record can be many seconds.
    SOCKADDR_INET addr{};
    bool          wantDns = false;
    {
        std::lock_guard<std::mutex> lock(sink.mutex);
        if (!sink.net)
            return;                       // engine already gone
        // Thread-safe copy of the hop's address (see OpenMTRNet::GetAddr).
        addr    = sink.net->GetAddr(args->index);
        wantDns = sink.net->opts.useDNS;
    }

    // The sockaddr length passed to getnameinfo must match the address
    // family — passing the larger sockaddr_in6 size for a v4 hop would be a
    // family/length mismatch that can make the lookup fail silently.
    const bool isV6  = (addr.Ipv6.sin6_family == AF_INET6);
    sockaddr*  sa    = isV6 ? reinterpret_cast<sockaddr*>(&addr.Ipv6) : reinterpret_cast<sockaddr*>(&addr.Ipv4);
    socklen_t  salen = isV6 ? sizeof(sockaddr_in6)  : sizeof(sockaddr_in);

    // Store a result only if the engine is still alive; re-checked for each
    // write, since the numeric and the PTR lookup are separated by the slow
    // resolver call.
    const auto publish = [&sink, &args](const char* name) {
        std::lock_guard<std::mutex> lock(sink.mutex);
        if (sink.net)
            sink.net->SetName(args->index, name);
    };

    if (!getnameinfo(sa, salen, hostname, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST))
        publish(hostname);

    if (wantDns) {
#ifdef _WIN32
        // The wide-character call, converted to UTF-8: getnameinfo() answers
        // in the ANSI code page, which cannot hold every name (and was then
        // widened byte by byte, garbling anything non-ASCII).
        wchar_t wide[NI_MAXHOST];
        if (!GetNameInfoW(sa, salen, wide, NI_MAXHOST, nullptr, 0, 0)
            && WideCharToMultiByte(CP_UTF8, 0, wide, -1, hostname, NI_MAXHOST, nullptr, nullptr) > 0)
            publish(hostname);
#else
        if (!getnameinfo(sa, salen, hostname, NI_MAXHOST, nullptr, 0, 0))
            publish(hostname);
#endif
    }
}

// ==========================================================================
//  Read accessors (locked)
// ==========================================================================

// Thread-safe copy of hop `at`'s address (v4 or v6). Returned by value, not
// as a pointer into the hop table, so the caller never holds a reference
// that could be read while another thread is writing it under m_mutex.
SOCKADDR_INET OpenMTRNet::GetAddr(int at)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    SOCKADDR_INET r = {};
    if (m_hops[at].addr6.sin6_family == AF_INET6) {
        r.Ipv6 = m_hops[at].addr6;
        r.Ipv6.sin6_family = AF_INET6;
#ifdef __APPLE__
        r.Ipv6.sin6_len = sizeof(sockaddr_in6);
#endif
    } else if (m_hops[at].addr.sin_family == AF_INET) {
        r.Ipv4 = m_hops[at].addr;
        r.Ipv4.sin_family = AF_INET;
#ifdef __APPLE__
        r.Ipv4.sin_len = sizeof(sockaddr_in);
#endif
    } else {
        r.Ipv4.sin_family = AF_UNSPEC;
    }
    return r;
}

// Full snapshot of hop `at` under a single lock — see the declaration in
// tracer.h for why this replaces taking the per-field getters one at a time.
OpenMTRNet::HopSnapshot OpenMTRNet::GetHopSnapshot(int at)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const HopRecord& h = m_hops[at];
    HopSnapshot s;

    if (h.addr6.sin6_family == AF_INET6) {
        s.addr.Ipv6 = h.addr6;
        s.addr.Ipv6.sin6_family = AF_INET6;
#ifdef __APPLE__
        s.addr.Ipv6.sin6_len = sizeof(sockaddr_in6);
#endif
    } else if (h.addr.sin_family == AF_INET) {
        s.addr.Ipv4 = h.addr;
        s.addr.Ipv4.sin_family = AF_INET;
#ifdef __APPLE__
        s.addr.Ipv4.sin_len = sizeof(sockaddr_in);
#endif
    } else {
        s.addr.Ipv4.sin_family = AF_UNSPEC;
    }

    s.xmit         = h.xmit;
    s.returned     = h.returned;
    s.altCount     = h.altCount;
    if (s.altCount > 0) s.altAddr = h.altAddr;
    s.anomalyCount = h.anomalyCount;
    s.anomalyLast  = h.anomalyLast;
    s.best         = h.best;
    s.worst        = h.worst;
    s.last         = h.last;
    s.total        = h.total;
    s.jitterSum    = h.jitterSum;
    strcpy_s(s.name, sizeof(s.name), h.name);
    return s;
}

// Route length as currently displayed: index just past the hop that carries
// the target address, or MAX_HOPS with trailing duplicates of the last
// responder trimmed. Reads the cache maintained by the address mutators
// (see RecalcMaxLocked), so it is a lock-free load, not a table scan.
int OpenMTRNet::GetMax()
{
    return m_maxHops.load(std::memory_order_relaxed);
}

// Recompute the route length; the caller must hold m_mutex. Scans the hop
// table until the target address appears (that index is the hop count). If
// the target was never seen (result == MAX_HOPS), trims trailing hops that
// merely repeat the last address or are empty, so the table doesn't end in
// identical/blank rows. Handles IPv4 and IPv6 separately.
int OpenMTRNet::RecalcMaxLocked()
{
    int max = 0;
    if (m_isV6) {
        for (; max < MAX_HOPS && memcmp(&m_hops[max++].addr6.sin6_addr, &last_remote_addr6, sizeof(in6_addr)););
        if (max == MAX_HOPS) {
            while (max > 1
                && !memcmp(&m_hops[max-1].addr6.sin6_addr, &m_hops[max-2].addr6.sin6_addr, sizeof(in6_addr))
#ifdef _WIN32
                && (m_hops[max-1].addr6.sin6_addr.u.Word[0] | m_hops[max-1].addr6.sin6_addr.u.Word[1]
                  | m_hops[max-1].addr6.sin6_addr.u.Word[2] | m_hops[max-1].addr6.sin6_addr.u.Word[3]
                  | m_hops[max-1].addr6.sin6_addr.u.Word[4] | m_hops[max-1].addr6.sin6_addr.u.Word[5]
                  | m_hops[max-1].addr6.sin6_addr.u.Word[6] | m_hops[max-1].addr6.sin6_addr.u.Word[7]))
#else
                // POSIX in6_addr has no .u.Word[] union; check the raw bytes
                // instead for "not the all-zeros address".
                && [](const in6_addr& a) {
                       for (int k = 0; k < 16; ++k)
                           if (a.s6_addr[k] != 0) return true;
                       return false;
                   }(m_hops[max-1].addr6.sin6_addr))
#endif
                --max;
        }
    } else {
        for (; max < MAX_HOPS && m_hops[max++].addr.sin_addr.s_addr != last_remote_addr.s_addr;);
        if (max == MAX_HOPS) {
            while (max > 1
                && m_hops[max-1].addr.sin_addr.s_addr == m_hops[max-2].addr.sin_addr.s_addr
                && m_hops[max-1].addr.sin_addr.s_addr)
                --max;
        }
    }
    return max;
}

// ==========================================================================
//  Mutators (locked)
// ==========================================================================

// Record hop `at`'s IPv4 address the first time we see it, and launch a
// background DNS resolver for it.
void OpenMTRNet::SetAddr(int at, u_long addr)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_hops[at].addr.sin_addr.s_addr != 0 &&
        m_hops[at].addr.sin_addr.s_addr != addr) {
        // A reply from a different address than the recorded one: a route
        // change or per-packet load balancing. The primary address stays
        // stable; remember the latest differing responder and count it.
        m_hops[at].altAddr = {};
        m_hops[at].altAddr.Ipv4.sin_family      = AF_INET;
        m_hops[at].altAddr.Ipv4.sin_addr.s_addr = addr;
        ++m_hops[at].altCount;
    }
    if (m_hops[at].addr.sin_addr.s_addr == 0) {
        m_hops[at].addr.sin_family      = AF_INET;
        m_hops[at].addr.sin_addr.s_addr = addr;
        auto* args  = new DnsResolverArgs;
        args->index = at;
        args->sink  = m_dnsSink;
#ifdef _WIN32
        if (_beginthread(DnsResolverThread, 0, args) == static_cast<uintptr_t>(-1))
            delete args;
#else
        // std::thread throws when the system has no thread to give; left
        // uncaught, that ends the whole process. The hop then keeps its
        // address for a name.
        try {
            std::thread([args]() { DnsResolverThread(args); }).detach();
        } catch (const std::system_error&) {
            delete args;
        }
#endif
    }
    m_maxHops.store(RecalcMaxLocked(), std::memory_order_relaxed);
}

// IPv6 version of SetAddr(): store the address once, then resolve its name.
void OpenMTRNet::SetAddr6(int at, IPV6_ADDRESS_EX addrex)
{
    std::lock_guard<std::mutex> lock(m_mutex);
#ifdef _WIN32
    const auto& w = m_hops[at].addr6.sin6_addr.u.Word;
    bool empty = !(w[0]|w[1]|w[2]|w[3]|w[4]|w[5]|w[6]|w[7]);
    if (!empty) {
        bool differs = false;
        for (int i = 0; i < 8 && !differs; ++i)
            differs = (w[i] != addrex.sin6_addr[i]);
        if (differs) {
            // See the IPv4 counterpart above.
            m_hops[at].altAddr = {};
            m_hops[at].altAddr.Ipv6.sin6_family = AF_INET6;
            for (int i = 0; i < 8; ++i)
                m_hops[at].altAddr.Ipv6.sin6_addr.u.Word[i] = addrex.sin6_addr[i];
            ++m_hops[at].altCount;
        }
    }
    if (empty) {
        m_hops[at].addr6.sin6_family = AF_INET6;
        for (int i = 0; i < 8; ++i)
            m_hops[at].addr6.sin6_addr.u.Word[i] = addrex.sin6_addr[i];
        auto* args  = new DnsResolverArgs;
        args->index = at;
        args->sink  = m_dnsSink;
        if (_beginthread(DnsResolverThread, 0, args) == static_cast<uintptr_t>(-1))
            delete args;
    }
#else
    // POSIX in6_addr has no .u.Word[] union; compare/copy the raw bytes.
    bool empty = true;
    for (int i = 0; i < 16; ++i) {
        if (m_hops[at].addr6.sin6_addr.s6_addr[i] != 0) {
            empty = false;
            break;
        }
    }
    if (!empty) {
        bool differs = std::memcmp(&m_hops[at].addr6.sin6_addr, &addrex.sin6_addr, 16) != 0;
        if (differs) {
            // See the IPv4 counterpart above.
            m_hops[at].altAddr = {};
            m_hops[at].altAddr.Ipv6.sin6_family = AF_INET6;
            std::memcpy(&m_hops[at].altAddr.Ipv6.sin6_addr, &addrex.sin6_addr, 16);
            ++m_hops[at].altCount;
        }
    }
    if (empty) {
        m_hops[at].addr6.sin6_family = AF_INET6;
        std::memcpy(&m_hops[at].addr6.sin6_addr, &addrex.sin6_addr, 16);
        auto* args  = new DnsResolverArgs;
        args->index = at;
        args->sink  = m_dnsSink;
        // std::thread throws when the system has no thread to give; left
        // uncaught, that ends the whole process. The hop then keeps its
        // address for a name.
        try {
            std::thread([args]() { DnsResolverThread(args); }).detach();
        } catch (const std::system_error&) {
            delete args;
        }
    }
#endif
    m_maxHops.store(RecalcMaxLocked(), std::memory_order_relaxed);
}

// Store the resolved host name for hop `at`. A PTR record can hold any
// bytes, and not every C library filters them, so control characters become
// '?' here: in the reports a line feed would start a new CSV row, and ESC a
// terminal escape sequence. U+0080 to U+009F are control characters too,
// two bytes each in UTF-8.
void OpenMTRNet::SetName(int at, const char* n)
{
    // Truncate rather than fail: strcpy_s() would empty the name (POSIX
    // shim) or abort the process (MSVC) on a name longer than the record,
    // and a UTF-8 name must not be cut inside a character.
    size_t len = strlen(n);
    if (len >= sizeof(m_hops[at].name)) {
        len = sizeof(m_hops[at].name) - 1;
        while (len > 0 && (static_cast<unsigned char>(n[len]) & 0xC0) == 0x80)
            --len;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    char*  name = m_hops[at].name;
    size_t out  = 0;
    for (size_t i = 0; i < len; ++i) {
        const unsigned char u    = static_cast<unsigned char>(n[i]);
        const unsigned char next = i + 1 < len ? static_cast<unsigned char>(n[i + 1]) : 0;
        if (u == 0xC2 && next >= 0x80 && next <= 0x9F) {
            name[out++] = '?';                       // U+0080..U+009F
            ++i;
        } else {
            name[out++] = (u < 0x20 || u == 0x7F) ? '?' : n[i];
        }
    }
    name[out] = '\0';
    m_hops[at].nameIsLocal = false;
}

// OpenMTR's own "Not sent" codes (tracer.h). Only the POSIX engine produces
// them, but SetErrorName() below is shared, so this is too.
static bool IsLocalStatus(DWORD st)
{
    return st > static_cast<DWORD>(OPENMTR_STATUS_BASE)
        && st <= static_cast<DWORD>(OPENMTR_NOT_SENT_OTHER);
}

// The sentence for a status code: what the Hostname column shows for a hop
// that has no name, and what the tooltip and the export print next to the
// number (see tracer.h).
const char* OpenMTRStatusText(unsigned long status, bool ipv6)
{
    // ipexport.h gives the ICMPv6 statuses the IPv4 numbers: 11002 is also
    // IP_DEST_NO_ROUTE, 11003 IP_DEST_ADDR_UNREACHABLE, 11014-11015 the
    // IPv6 reassembly-time-exceeded and parameter-problem codes, all close
    // enough to the IPv4 sentence (11013, hop limit exceeded, is a normal
    // reply and never gets here). 11004 is not: for IPv6 it is IP_DEST_PROHIBITED
    // (ICMPv6 has no "protocol unreachable"). Only the Windows engine can
    // produce it for an IPv6 trace; the POSIX one reports that ICMPv6 code
    // as IP_BAD_ROUTE.
    if (ipv6 && status == IP_DEST_PROT_UNREACHABLE)
        return "Communication administratively prohibited.";
    switch (status) {
    case IP_BUF_TOO_SMALL:            return "Reply buffer too small.";
    case IP_DEST_NET_UNREACHABLE:     return "Destination network unreachable.";
    case IP_DEST_HOST_UNREACHABLE:    return "Destination host unreachable.";
    case IP_DEST_PROT_UNREACHABLE:    return "Destination protocol unreachable.";
    case IP_DEST_PORT_UNREACHABLE:    return "Destination port unreachable.";
    case IP_NO_RESOURCES:             return "Insufficient IP resources.";
    case IP_BAD_OPTION:               return "Bad IP option.";
    case IP_HW_ERROR:                 return "Hardware error.";
    case IP_PACKET_TOO_BIG:           return "Packet too big.";
    case IP_REQ_TIMED_OUT:            return "Request timed out.";
    case IP_BAD_REQ:                  return "Bad request.";
    case IP_BAD_ROUTE:                return "Bad route.";
    case IP_TTL_EXPIRED_REASSEM:      return "TTL expired during reassembly.";
    case IP_PARAM_PROBLEM:            return "Parameter problem.";
    case IP_SOURCE_QUENCH:            return "Source quench.";
    case IP_OPTION_TOO_BIG:           return "IP option too big.";
    case IP_BAD_DESTINATION:          return "Bad destination.";
    case IP_GENERAL_FAILURE:          return "General failure.";
    case OPENMTR_NOT_SENT_NO_ROUTE:   return "Not sent: no route from this machine.";
    case OPENMTR_NOT_SENT_NO_ADDRESS: return "Not sent: no usable local address.";
    case OPENMTR_NOT_SENT_TOO_BIG:    return "Not sent: probe too large.";
    case OPENMTR_NOT_SENT_NO_BUFFERS: return "Not sent: out of buffer space.";
    case OPENMTR_NOT_SENT_REFUSED:    return "Not sent: refused by this machine.";
    case OPENMTR_NOT_SENT_OTHER:      return "Not sent: local error.";
    default:                          return "Unknown error.";
    }
}

// Translate a status code into readable text. Only applied when the hop has
// no name yet, so a real host name always wins — with one exception: a
// "Not sent" text is provisional. A burst of local failures (IPv6 dropping
// for a few seconds) would otherwise label a silent hop for the rest of the
// trace; the next non-local status replaces it instead.
void OpenMTRNet::SetErrorName(int at, DWORD errnum)
{
    const char* name = OpenMTRStatusText(errnum, m_isV6);
    const bool local = IsLocalStatus(errnum);
    std::lock_guard<std::mutex> lock(m_mutex);
    HopRecord& h = m_hops[at];
    if (!*h.name || (h.nameIsLocal && !local)) {
        strcpy_s(h.name, sizeof(h.name), name);
        h.nameIsLocal = local;
    }
}

// Record one completed probe atomically: bump xmit and, per outcome, either
// the reply statistics (returned, RTT figures, jitter) or the anomaly
// bookkeeping. A single lock covers everything, so a snapshot can never see
// a probe as sent-but-unaccounted. Plain timeouts pass anomaly == 0.
void OpenMTRNet::RecordProbe(int at, bool replied, int rtt, unsigned long anomaly)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_hops[at].xmit;
    if (replied) {
        // Jitter: |difference| against the previous reply's RTT; the very
        // first reply has no predecessor and contributes no difference.
        if (m_hops[at].returned > 0)
            m_hops[at].jitterSum += (rtt > m_hops[at].last) ? static_cast<unsigned long>(rtt - m_hops[at].last)
                                                            : static_cast<unsigned long>(m_hops[at].last - rtt);
        m_hops[at].last   = rtt;
        m_hops[at].total += rtt;
        if (m_hops[at].returned == 0 || m_hops[at].best > rtt) m_hops[at].best = rtt;
        if (m_hops[at].worst < rtt)                            m_hops[at].worst = rtt;
        ++m_hops[at].returned;
        // Track the farthest hop that ever answered (1-based); written under
        // m_mutex, read lock-free by the dispatch loop's parking logic.
        if (at + 1 > m_lastAlive.load(std::memory_order_relaxed))
            m_lastAlive.store(at + 1, std::memory_order_relaxed);
    } else if (anomaly != 0) {
        ++m_hops[at].anomalyCount;
        m_hops[at].anomalyLast = anomaly;
    }
}

