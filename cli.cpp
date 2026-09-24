// ==========================================================================
//  cli.cpp — headless report mode (OpenMTR --report ...)
//
//  The window's trace without the window: resolve the target, let the route
//  settle, count a fixed number of probe cycles, then print the same report
//  Copy/Export produce (text or JSON) to stdout and exit. Only QtCore is
//  used — no QApplication, so it runs over SSH, from cron or in CI with no
//  display at all.
//
//  Exit codes (also listed in --help):
//    0    report printed, the destination replied
//    1    report printed, the destination never replied
//    2    invalid command line
//    3    the target could not be resolved
//    4    the trace could not start (no ICMP socket / handle)
//    130  interrupted (Ctrl+C); the partial report is still printed
// ==========================================================================

#include "cli.h"
#include "report.h"
#include "version.h"

#include <QtCore/QCommandLineOption>
#include <QtCore/QCommandLineParser>
#include <QtCore/QCoreApplication>
#include <QtCore/QDateTime>
#include <QtCore/QJsonObject>
#include <QtCore/QString>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stop_token>
#include <thread>
#include <vector>

namespace {

// ==========================================================================
//  Constants
// ==========================================================================

enum ExitCode {
    ExitOk          = 0,
    ExitNoReply     = 1,
    ExitUsage       = 2,
    ExitResolve     = 3,
    ExitEngine      = 4,
    ExitInterrupted = 130,
};

constexpr int    kDefaultCount = 10;
constexpr int    kMaxCount     = 100000;
constexpr double kMinInterval  = 0.1;
constexpr double kMaxInterval  = 60.0;
// Same range as the window's ping size box.
constexpr int    kMinSize      = 64;
constexpr int    kMaxSize      = 8192;

using Clock = std::chrono::steady_clock;
using Ms    = std::chrono::milliseconds;

// How often the run loops below look at the engine.
constexpr Ms kPollStep{100};
// Warm-up: like the window, statistics start only once the discovered route
// holds steady, so the report does not mix in discovery probes. The window
// waits for more (every silent hop to time out twice, so no row pops in
// after the reveal); a report is printed only at the end, so it needs just
// a stable route. Probes to the 30 TTLs start 50 ms apart, so the route
// cannot settle in less than about 1.5 s. The deadline is the window's.
constexpr Ms kWarmupMinStable{2000};
constexpr Ms kWarmupDeadline{12000};
// After counting: time given to reverse-DNS names and ASN lookups still in
// flight. A name that has not come by then is left as the bare address.
constexpr Ms kNameGrace{3000};
constexpr Ms kNameStall{1000};

// ==========================================================================
//  Output
// ==========================================================================

void writeTo(FILE* f, const QString& text)
{
    const QByteArray bytes = text.toUtf8();
    std::fwrite(bytes.constData(), 1, static_cast<size_t>(bytes.size()), f);
    std::fflush(f);
}

void printError(const QString& text)
{
    writeTo(stderr, QStringLiteral("OpenMTR: %1\n").arg(text));
}

#ifdef _WIN32
// OpenMTR.exe is a GUI-subsystem program, so Windows gives it no console:
// stdout and stderr only work where the shell redirected them to a file or
// pipe. Anything left pointing nowhere is sent to the console of the shell
// that started us instead.
bool isRedirected(DWORD which)
{
    const HANDLE h = GetStdHandle(which);
    if (!h || h == INVALID_HANDLE_VALUE)
        return false;
    const DWORD type = GetFileType(h);
    return type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE;
}

void attachParentConsole()
{
    const bool outRedirected = isRedirected(STD_OUTPUT_HANDLE);
    const bool errRedirected = isRedirected(STD_ERROR_HANDLE);
    if (outRedirected && errRedirected)
        return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS))
        return;                       // started without a console (Explorer, a service)
    FILE* stream = nullptr;
    if (!outRedirected)
        freopen_s(&stream, "CONOUT$", "w", stdout);
    if (!errRedirected)
        freopen_s(&stream, "CONOUT$", "w", stderr);
    // Host names and the report's notes are UTF-8.
    SetConsoleOutputCP(CP_UTF8);
}
#endif

// ==========================================================================
//  Interruption
// ==========================================================================

std::atomic<bool> g_interrupted{false};

// First Ctrl+C (or SIGTERM): finish early and still print what was
// measured. The default action is restored, so a second one ends the
// process at once.
extern "C" void onInterrupt(int sig)
{
    g_interrupted.store(true);
    std::signal(sig, SIG_DFL);
}

// ==========================================================================
//  Target & engine helpers
// ==========================================================================

// Resolve `target`. `family` is AF_INET or AF_INET6 when -4/-6 forced one,
// else AF_UNSPEC: IPv4 preferred, IPv6 as the fallback, as in the window.
bool resolveTarget(const QString& target, int family, SOCKADDR_INET& out)
{
    addrinfo hints = {}, *res = nullptr;
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM;   // one entry per address, not per socket type
    if (getaddrinfo(target.toStdString().c_str(), nullptr, &hints, &res) != 0 || !res)
        return false;
    auto resGuard = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>(res, freeaddrinfo);

    const addrinfo* match = nullptr;
    for (const int want : {AF_INET, AF_INET6})
        for (const addrinfo* r = res; r && !match; r = r->ai_next)
            if (r->ai_family == want) match = r;
    if (!match)
        return false;
    out = {};
    std::memcpy(&out, match->ai_addr,
                match->ai_addrlen < sizeof(out) ? match->ai_addrlen : sizeof(out));
    return true;
}

bool isV6(const SOCKADDR_INET& a)  { return a.Ipv6.sin6_family == AF_INET6; }
bool hasAddr(const SOCKADDR_INET& a) { return a.Ipv4.sin_family != AF_UNSPEC; }

bool sameAddress(const SOCKADDR_INET& a, const SOCKADDR_INET& b)
{
    if (a.Ipv4.sin_family != b.Ipv4.sin_family)
        return false;
    if (a.Ipv4.sin_family == AF_INET)
        return std::memcmp(&a.Ipv4.sin_addr, &b.Ipv4.sin_addr, sizeof(a.Ipv4.sin_addr)) == 0;
    if (a.Ipv6.sin6_family == AF_INET6)
        return std::memcmp(&a.Ipv6.sin6_addr, &b.Ipv6.sin6_addr, sizeof(a.Ipv6.sin6_addr)) == 0;
    return false;
}

QString addressText(const SOCKADDR_INET& a)
{
    return QString::fromStdWString(addr_to_wstring(a));
}

// The route as the window's warm-up sees it: hop count plus every hop's
// address. Any change restarts the stability window.
QByteArray routeFingerprint(const std::vector<OpenMTRHostInfo>& state)
{
    QByteArray fp;
    fp.append(static_cast<char>(state.size()));
    for (const auto& h : state) {
        if (h.addr.Ipv4.sin_family == AF_INET)
            fp.append(reinterpret_cast<const char*>(&h.addr.Ipv4.sin_addr), sizeof(h.addr.Ipv4.sin_addr));
        else if (h.addr.Ipv6.sin6_family == AF_INET6)
            fp.append(reinterpret_cast<const char*>(&h.addr.Ipv6.sin6_addr), sizeof(h.addr.Ipv6.sin6_addr));
        else
            fp.append('\0');
    }
    return fp;
}

// ASN lookups, one detached thread per address as it appears (the window
// does the same), so they run while probes are counted. Shared with the
// threads, which may outlive a run cut short.
struct AsnCache {
    std::mutex                 mutex;
    std::map<QString, QString> results;   // address -> AS number ("" = none)
    std::set<QString>          pending;

    void request(const QString& ip, bool v6, const std::shared_ptr<AsnCache>& self)
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (results.count(ip) || !pending.insert(ip).second)
                return;
        }
        std::thread([self, ip, v6] {
            const QString asn = lookupAsn(ip, v6);
            std::lock_guard<std::mutex> lock(self->mutex);
            self->pending.erase(ip);
            self->results[ip] = asn;
        }).detach();
    }
    QString get(const QString& ip)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = results.find(ip);
        return it == results.end() ? QString() : it->second;
    }
    bool busy()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return !pending.empty();
    }
};

} // namespace

// ==========================================================================
//  Entry points
// ==========================================================================

bool isReportModeRequested(int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!std::strcmp(a, "--report") || !std::strcmp(a, "-r")
            || !std::strcmp(a, "--help") || !std::strcmp(a, "-h") || !std::strcmp(a, "-?")
            || !std::strcmp(a, "--version") || !std::strcmp(a, "-v"))
            return true;
    }
    return false;
}

int runReportMode(int argc, char* argv[])
{
#ifdef _WIN32
    attachParentConsole();
#endif

    QCoreApplication app(argc, argv);
    app.setApplicationName("OpenMTR");
    app.setApplicationVersion(OPENMTR_VERSION);

    // ---- Command line ------------------------------------------------------
    QCommandLineParser parser;
    parser.setApplicationDescription(
        "OpenMTR report mode: trace the route to <target> for a fixed number of\n"
        "cycles, print the report to stdout and exit, without opening a window.\n"
        "\n"
        "Exit codes:\n"
        "  0    report printed, the destination replied\n"
        "  1    report printed, the destination never replied\n"
        "  2    invalid command line\n"
        "  3    the target could not be resolved\n"
        "  4    the trace could not start (no ICMP socket)\n"
        "  130  interrupted with Ctrl+C (the partial report is still printed)");
    const QCommandLineOption reportOpt({"r", "report"},
        "Run without a window and print a report (required).");
    const QCommandLineOption countOpt({"c", "count"},
        QString("Probe cycles to count before reporting (default %1).").arg(kDefaultCount), "N");
    const QCommandLineOption intervalOpt({"i", "interval"},
        QString("Seconds between probes to each hop, %1 to %2 (default 1).").arg(kMinInterval).arg(kMaxInterval),
        "seconds");
    const QCommandLineOption sizeOpt({"s", "size"},
        QString("ICMP payload size in bytes, %1 to %2 (default %1).").arg(kMinSize).arg(kMaxSize), "bytes");
    const QCommandLineOption v4Opt("4", "Use IPv4 only.");
    const QCommandLineOption v6Opt("6", "Use IPv6 only.");
    const QCommandLineOption noDnsOpt({"n", "no-dns"}, "Do not resolve host names of hops.");
    const QCommandLineOption noAsnOpt("no-asn", "Do not look up AS numbers.");
    const QCommandLineOption jsonOpt({"j", "json"}, "Print the report as JSON.");
    const QCommandLineOption helpOpt({"h", "?", "help"}, "Show this help and exit.");
    const QCommandLineOption versionOpt({"v", "version"}, "Show the version and exit.");
    for (const auto* o : {&reportOpt, &countOpt, &intervalOpt, &sizeOpt, &v4Opt, &v6Opt,
                          &noDnsOpt, &noAsnOpt, &jsonOpt, &helpOpt, &versionOpt})
        parser.addOption(*o);
    parser.addPositionalArgument("target", "Host name or IP address to trace.");

    // parse(), not process(): process() would print (or, in a Windows GUI
    // program, show a message box) and exit on its own terms.
    if (!parser.parse(app.arguments())) {
        printError(parser.errorText() + "\nTry 'OpenMTR --help'.");
        return ExitUsage;
    }
    if (parser.isSet(helpOpt)) {
        writeTo(stdout, parser.helpText());
        return ExitOk;
    }
    if (parser.isSet(versionOpt)) {
        writeTo(stdout, QStringLiteral("OpenMTR %1\n").arg(OPENMTR_VERSION));
        return ExitOk;
    }

    auto usageError = [](const QString& text) {
        printError(text + "\nTry 'OpenMTR --help'.");
        return ExitUsage;
    };
    if (!parser.isSet(reportOpt))
        return usageError("--report is required to run without a window.");
    const QStringList positional = parser.positionalArguments();
    if (positional.size() != 1)
        return usageError(positional.isEmpty() ? QStringLiteral("No target given.")
                                               : QStringLiteral("Only one target can be given."));
    const QString target = positional.first();

    int count = kDefaultCount;
    if (parser.isSet(countOpt)) {
        bool ok = false;
        count = parser.value(countOpt).toInt(&ok);
        if (!ok || count < 1 || count > kMaxCount)
            return usageError(QString("--count must be a whole number from 1 to %1.").arg(kMaxCount));
    }
    double interval = 1.0;
    if (parser.isSet(intervalOpt)) {
        bool ok = false;
        interval = parser.value(intervalOpt).toDouble(&ok);
        if (!ok || !(interval >= kMinInterval && interval <= kMaxInterval))
            return usageError(QString("--interval must be from %1 to %2 seconds.").arg(kMinInterval).arg(kMaxInterval));
    }
    int size = kMinSize;
    if (parser.isSet(sizeOpt)) {
        bool ok = false;
        size = parser.value(sizeOpt).toInt(&ok);
        if (!ok || size < kMinSize || size > kMaxSize)
            return usageError(QString("--size must be from %1 to %2 bytes.").arg(kMinSize).arg(kMaxSize));
    }
    if (parser.isSet(v4Opt) && parser.isSet(v6Opt))
        return usageError("-4 and -6 cannot be used together.");
    const int family = parser.isSet(v4Opt) ? AF_INET : parser.isSet(v6Opt) ? AF_INET6 : AF_UNSPEC;
    const bool useDns = !parser.isSet(noDnsOpt);
    const bool useAsn = !parser.isSet(noAsnOpt);
    const bool json   = parser.isSet(jsonOpt);

    // ---- Target ------------------------------------------------------------
    SOCKADDR_INET dest = {};
    if (!resolveTarget(target, family, dest)) {
        printError(family == AF_INET  ? QString("Could not resolve \"%1\" to an IPv4 address.").arg(target)
                 : family == AF_INET6 ? QString("Could not resolve \"%1\" to an IPv6 address.").arg(target)
                                      : QString("Could not resolve \"%1\".").arg(target));
        return ExitResolve;
    }
    const bool v6 = isV6(dest);

    // ---- Trace -------------------------------------------------------------
    std::signal(SIGINT, onInterrupt);
#ifdef SIGTERM
    std::signal(SIGTERM, onInterrupt);
#endif

    const auto engineError = [] {
#ifdef __linux__
        printError("Could not open an ICMP socket. Unprivileged ping sockets may be "
                   "disabled; allow them with: sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"");
#else
        printError("Could not open an ICMP socket.");
#endif
        return ExitEngine;
    };

    OpenMTROptions opts;
    opts.pingsize = static_cast<unsigned>(size);
    opts.interval = interval;
    opts.useDNS   = useDns;

    auto net = std::make_unique<OpenMTRNetWrapper>();
    std::stop_source stop;
    if (net->DoTrace(stop.get_token(), dest, opts) != 0)
        return engineError();

    auto asn = std::make_shared<AsnCache>();
    auto requestAsns = [&](const std::vector<OpenMTRHostInfo>& state) {
        if (!useAsn) return;
        for (const auto& h : state)
            if (hasAddr(h.addr))
                asn->request(addressText(h.addr), isV6(h.addr), asn);
    };

    // Warm-up: until the route holds steady (or the deadline passes).
    const auto traceStart = Clock::now();
    // Moved to the start of counting below; kept here should Ctrl+C end the
    // run during the warm-up.
    QDateTime started = QDateTime::currentDateTime();
    auto countStart   = traceStart;
    const Ms   minStable  = std::max(kWarmupMinStable, Ms(static_cast<long long>(interval * 1000) + 250));
    QByteArray fingerprint;
    auto lastChange = traceStart;
    while (!g_interrupted.load()) {
        std::this_thread::sleep_for(kPollStep);
        // The engine only ends on its own when it could not open its socket.
        if (net->isDone())
            return engineError();
        const auto state = net->getCurrentState();
        requestAsns(state);
        const QByteArray fp = routeFingerprint(state);
        const auto now = Clock::now();
        if (fp != fingerprint) {
            fingerprint = fp;
            lastChange  = now;
        }
        if (now - lastChange >= minStable || now - traceStart >= kWarmupDeadline)
            break;
    }

    // Counting: statistics restart now, so they describe this window only.
    // Done once every hop that replies has been probed `count` times and
    // every other hop has at least one finished probe, so no row is left
    // without a result. Probes to a silent hop only finish when they time
    // out (5 s each), so hops that never or rarely reply cannot hold the
    // report up beyond the time `count` cycles take plus one timeout.
    if (!g_interrupted.load()) {
        net->resetStats();
        started    = QDateTime::currentDateTime();
        countStart = Clock::now();
        const auto deadline = countStart
            + Ms(static_cast<long long>(count * interval * 1000) + ECHO_REPLY_TIMEOUT + 1000);
        while (!g_interrupted.load()) {
            std::this_thread::sleep_for(kPollStep);
            if (net->isDone())
                return engineError();
            const auto state = net->getCurrentState();
            requestAsns(state);
            int  maxSent = 0;
            bool done    = true;
            for (const auto& h : state) {
                maxSent = std::max(maxSent, h.xmit);
                if (h.xmit == 0 || (h.returned > 0 && h.xmit < count))
                    done = false;
            }
            if ((done && maxSent >= count) || Clock::now() >= deadline)
                break;
        }
    }
    const qint64 durationMs =
        std::chrono::duration_cast<Ms>(Clock::now() - countStart).count();
    const bool interrupted = g_interrupted.load();

    // Stop probing. The engine object stays alive, so reverse-DNS answers
    // still in flight can land while we wait for them below.
    stop.request_stop();
    while (!net->isDone())
        std::this_thread::sleep_for(Ms(10));

    if (!interrupted) {
        const auto graceEnd = Clock::now() + kNameGrace;
        int  named = -1;
        auto lastProgress = Clock::now();
        while (Clock::now() < graceEnd && !g_interrupted.load()) {
            const auto state = net->getCurrentState();
            requestAsns(state);
            int addressed = 0, nowNamed = 0;
            for (const auto& h : state) {
                if (!hasAddr(h.addr)) continue;
                ++addressed;
                if (h.getName() != addr_to_wstring(h.addr)) ++nowNamed;
            }
            if (nowNamed > named) {
                named = nowNamed;
                lastProgress = Clock::now();
            }
            const bool namesSettled = !useDns || nowNamed >= addressed
                                   || Clock::now() - lastProgress >= kNameStall;
            if (namesSettled && !asn->busy())
                break;
            std::this_thread::sleep_for(kPollStep);
        }
    }

    // ---- Report ------------------------------------------------------------
    const auto state = net->getCurrentState();
    std::vector<ReportRow> rows;
    bool reached = false;
    for (int i = 0; i < static_cast<int>(state.size()); ++i) {
        const auto& h = state[i];
        rows.push_back(makeReportRow(i, h, hasAddr(h.addr) && useAsn ? asn->get(addressText(h.addr)) : QString()));
        if (sameAddress(h.addr, dest) && h.returned > 0)
            reached = true;
    }

    ReportInfo info;
    info.title      = QStringLiteral("OpenMTR Report");
    info.target     = target;
    info.address    = addressText(dest);
    info.started    = started;
    info.durationMs = durationMs;
    info.ipv6       = v6;

    if (json) {
        QJsonObject extra;
        extra["address"]             = info.address;
        extra["ip_version"]          = v6 ? 6 : 4;
        extra["count"]               = count;
        extra["interval"]            = interval;
        extra["size"]                = size;
        extra["destination_reached"] = reached;
        extra["interrupted"]         = interrupted;
        writeTo(stdout, buildJsonReport(info, rows, extra));
    } else {
        writeTo(stdout, buildTextReport(info, rows));
    }
    if (interrupted)
        printError("Interrupted; the report covers only the probes sent so far.");

    const int rc = interrupted ? ExitInterrupted : reached ? ExitOk : ExitNoReply;

    // ASN lookups still running (a slow resolver, or a run cut short) hold
    // a reference to Qt; tearing QCoreApplication down under them is not
    // safe. Everything worth keeping has been written, so leave at once.
    if (asn->busy()) {
        std::fflush(nullptr);
        std::_Exit(rc);
    }
    return rc;
}
