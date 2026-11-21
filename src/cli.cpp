// ==========================================================================
//  cli.cpp — headless report mode (`OpenMTR --report ...`)
//
//  The window's trace without the window: resolve the target, wait for the
//  route to settle using the exact same conditions as MainWindow's warm-up
//  (see report_core.h — that is the whole point of sharing the code, not
//  reimplementing it), count for the requested duration, then print the
//  same report Copy/Export would produce (text, JSON or CSV) to stdout and
//  exit.
//
//  Part of the Qt-free core: standard C++ and the C library only (output
//  through stdio), so the same code runs inside the window app and in a
//  build without Qt at all. No window, no event loop, no display needed.
//
//  Exit codes:
//    0    report printed, the destination replied
//    1    report printed, the destination never replied during the run
//    2    invalid command line
//    3    the target could not be resolved
//    4    the trace could not start (no ICMP socket/handle)
//    5    the report could not be written to --output
//    130  interrupted (Ctrl+C); the partial report is still printed
// ==========================================================================

#include "cli.h"
#include "report_core.h"
#include "asncache.h"
#include "textutil.h"
#include "tracer.h"
#include "versioninfo.h"
#if OPENMTR_ENABLE_UPDATE_CHECK
#include "updatecheck.h"
#endif

// tracer.h (included above) already pulls in winsock2/ws2tcpip/windows.h on
// Windows and netdb.h/arpa/inet.h/unistd.h on POSIX — everything
// getaddrinfo(), SetConsoleCtrlHandler() and isatty() below need. Only
// _isatty/_fileno live in <io.h>, and CommandLineToArgvW in <shellapi.h>.
#ifdef _WIN32
#include <io.h>
#include <shellapi.h>
#endif

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <stop_token>
#include <thread>
#include <vector>

namespace {

enum ExitCode {
    ExitOk          = 0,
    ExitNoReply     = 1,
    ExitUsage       = 2,
    ExitResolve     = 3,
    ExitEngine      = 4,
    ExitOutputError = 5,
    ExitInterrupted = 130,
};

// Set by the Ctrl+C handler, polled by run()'s loops. A lock-free atomic is
// all a POSIX signal handler may touch: the handler used to call
// std::stop_source::request_stop() as well, which takes locks and runs the
// engine's stop callback - not async-signal-safe, so a Ctrl+C landing at
// the wrong moment could deadlock. run() requests the stop itself, on its
// own thread, within one loop tick (at most 250 ms) of seeing this flag.
std::atomic<bool> g_interrupted{false};
static_assert(std::atomic<bool>::is_always_lock_free,
              "the Ctrl+C handler needs a lock-free flag");

#ifdef _WIN32
BOOL WINAPI consoleCtrlHandler(DWORD signalType)
{
    if (signalType == CTRL_C_EVENT || signalType == CTRL_BREAK_EVENT) {
        g_interrupted.store(true);
        return TRUE;
    }
    return FALSE;
}
#else
void sigintHandler(int)
{
    g_interrupted.store(true);
}
#endif

#ifdef _WIN32
std::wstring wideFromUtf8(const std::string& text)
{
    if (text.empty())
        return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n);
    return out;
}

std::string utf8FromWide(const wchar_t* text)
{
    const int n = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1)
        return std::string();
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), n, nullptr, nullptr);
    out.resize(static_cast<size_t>(n - 1));
    return out;
}
#endif

// The system's message for an errno value (strerror_s on Windows, where
// MSVC deprecates strerror).
std::string errnoText(int err)
{
#ifdef _WIN32
    char buf[256] = {};
    strerror_s(buf, sizeof(buf), err);
    return buf;
#else
    return std::strerror(err);
#endif
}

// Writes UTF-8 text that may contain non-ASCII characters (the "·" in
// --version, a hostname from a reverse lookup) to a stdio stream that may be
// a real Windows console, or may have been redirected to a file or a pipe -
// rendering correctly either way.
//
// The first approach here was SetConsoleOutputCP(CP_UTF8) around the whole
// run, on the theory that the console's output code page (852 on a Czech
// system, turning "·" - bytes C2 B7 - into "┬Ě") just needed switching to
// UTF-8 for the duration. It did not reliably work: a console's code page is
// separate from its font, older conhost's raster ("Terminal") font cannot
// render code page 65001 at all, and buffered CRT stdio (printf/fputs) going
// through it does not consistently pick up the change either - the same
// "┬Ě" kept appearing. Switching a shared, outlived-by-us piece of console
// state and having to restore it afterwards was also more machinery than the
// problem needed.
//
// The reliable fix sidesteps code pages entirely: when the destination is an
// actual console, convert to UTF-16 and call WriteConsoleW, which Windows
// always renders correctly regardless of the console's code page or font.
// When the destination is not a console (redirected to a file, piped into
// another program), there is no code page or font to fight, and the other
// end expects UTF-8 bytes - exactly what this always wrote and what the
// non-Windows branch below still writes.
#ifdef _WIN32
void writeText(FILE* stream, const std::string& text)
{
    const HANDLE handle = GetStdHandle(stream == stdout ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    DWORD consoleMode = 0;
    if (handle != INVALID_HANDLE_VALUE && GetConsoleMode(handle, &consoleMode)) {
        const std::wstring utf16 = wideFromUtf8(text);
        DWORD written = 0;
        WriteConsoleW(handle, utf16.c_str(), static_cast<DWORD>(utf16.size()), &written, nullptr);
        return;
    }
    std::fputs(text.c_str(), stream);
}
#else
void writeText(FILE* stream, const std::string& text)
{
    std::fputs(text.c_str(), stream);
}
#endif

// True when stderr is an actual terminal a human is watching, as opposed to
// redirected to a file/pipe (`--report ... > report.txt`, a cron/Task
// Scheduler log, `| findstr ...`). Progress updates only make sense in the
// first case — in the second they would just be junk bytes sitting in a log
// file forever, since nothing ever prints a newline after a \r update.
bool stderrIsInteractive()
{
#ifdef _WIN32
    return _isatty(_fileno(stderr)) != 0;
#else
    return isatty(fileno(stderr)) != 0;
#endif
}

// Prints a single self-overwriting status line to stderr (never stdout —
// stdout is reserved for the report itself, so piping/redirecting it must
// never see progress noise mixed in). No-op when stderr isn't a terminal.
// The messages are ASCII, so bytes are columns.
class Progress {
public:
    explicit Progress(bool enabled) : m_enabled(enabled) {}

    void update(const std::string& text)
    {
        if (!m_enabled || m_finished) return;
        // Pad over whatever was on the line before (a shorter message
        // following a longer one would otherwise leave a stale tail).
        std::string line = "\r" + text;
        if (text.size() < m_lastLen) line.append(m_lastLen - text.size(), ' ');
        m_lastLen = text.size();
        std::fputs(line.c_str(), stderr);
        std::fflush(stderr);
    }

    // Clears the line so whatever prints next (the report, on stdout, or
    // just the shell prompt) doesn't end up sharing it — e.g. "Finishing..."
    // followed directly by "OpenMTR Export" with no line break between them.
    // Idempotent and called explicitly right before the report is printed;
    // the destructor is just a safety net for any path that returns early.
    void finish()
    {
        if (!m_enabled || m_finished) return;
        m_finished = true;
        const std::string out = "\r" + std::string(m_lastLen, ' ') + "\r";
        std::fputs(out.c_str(), stderr);
        std::fflush(stderr);
    }

    ~Progress() { finish(); }

private:
    bool   m_enabled;
    bool   m_finished = false;
    size_t m_lastLen  = 0;
};

// 1 in the window app; 0 in a build without it, which runs report mode
// whether or not `--report` is given (see main.cpp).
#ifndef OPENMTR_GUI
#define OPENMTR_GUI 1
#endif

// How this program was started (argv[0] without its directory or ".exe"),
// for the usage line of a build without the window, which a package may
// install under another name ("openmtr" on OpenWrt).
std::string g_programName = "OpenMTR";

void setProgramName(const char* argv0)
{
    if (!argv0 || !*argv0)
        return;
    std::string name = argv0;
    const size_t slash = name.find_last_of("/\\");
    if (slash != std::string::npos)
        name.erase(0, slash + 1);
    if (name.size() > 4) {
        std::string ext = name.substr(name.size() - 4);
        for (char& c : ext)
            c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        if (ext == ".exe")
            name.resize(name.size() - 4);
    }
    if (!name.empty())
        g_programName = name;
}

void printUsage(FILE* out)
{
#if OPENMTR_GUI
    std::fputs("OpenMTR --report --time <sec> [options] <target>\n", out);
#else
    std::fprintf(out, "%s [--report] --time <sec> [options] <target>\n", g_programName.c_str());
#endif
    std::fprintf(out,
        "  --time <sec>        measure duration (required)\n"
        "  --size <bytes>      payload, 64-8192\n"
        "  -4 | -6             force IP version\n"
        "  --txt|--json|--csv  format (default: txt)\n"
        "  --output <file>     write to file\n"
        "  -v                  version\n");
}

class CliOptionsProvider : public IOpenMTROptionsProvider {
public:
    explicit CliOptionsProvider(unsigned size) : m_size(size) {}
    [[nodiscard]] unsigned getPingSize() const noexcept override { return m_size; }
private:
    unsigned m_size;
};

// Resolves `target`, preferring `wantFamily` but falling back to whatever
// address family is available — identical to MainWindow::onStartStop()'s
// Start path, so a target that behaves one way in the GUI behaves the same
// way here.
bool resolveTarget(const std::string& target, int wantFamily, SOCKADDR_INET& addr, bool& ipv6)
{
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    ipv6 = (wantFamily == AF_INET6);
    bool resolved = false;

    if (getaddrinfo(target.c_str(), nullptr, &hints, &res) == 0 && res) {
        addrinfo* match = nullptr;
        for (addrinfo* r = res; r; r = r->ai_next)
            if (r->ai_family == wantFamily) { match = r; break; }
        if (!match)
            for (addrinfo* r = res; r; r = r->ai_next)
                if (r->ai_family == AF_INET || r->ai_family == AF_INET6) { match = r; break; }
        if (match) {
            std::memcpy(&addr, match->ai_addr,
                match->ai_addrlen < sizeof(addr) ? match->ai_addrlen : sizeof(addr));
            ipv6 = (match->ai_family == AF_INET6);
            resolved = true;
        }
        freeaddrinfo(res);
    }
    return resolved;
}

// Writes the report to --output: directly by us, independent of the shell,
// so it works with no shell or console at all (Task Scheduler, a service)
// and without depending on how a given shell implements redirection. Text
// mode, so Windows gets CRLF line ends as a QIODevice::Text file did.
// Returns 0 or the errno value of the failure.
int writeReportFile(const std::string& path, const std::string& report)
{
#ifdef _WIN32
    FILE* f = nullptr;
    if (const errno_t err = _wfopen_s(&f, wideFromUtf8(path).c_str(), L"w"); err != 0 || !f)
        return err != 0 ? err : EIO;
#else
    FILE* f = std::fopen(path.c_str(), "w");
    if (!f)
        return errno != 0 ? errno : EIO;
#endif
    const size_t written = std::fwrite(report.data(), 1, report.size(), f);
    const int    writeErr = (written != report.size()) ? (errno != 0 ? errno : EIO) : 0;
    if (std::fclose(f) != 0 && writeErr == 0)
        return errno != 0 ? errno : EIO;
    return writeErr;
}

}  // namespace

cli::ParseResult cli::parseArgs(int argc, char** argv, Options& opts, std::string& error)
{
    opts = Options{};
    bool haveTime   = false;
    bool haveFormat = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];

        if (a == "--report") {
            continue;   // mode selector; main() already acted on it
        } else if (a == "-h" || a == "--h" || a == "--help") {
            return ParseResult::Help;
        } else if (a == "--time") {
            if (++i >= argc) { error = "--time needs a value"; return ParseResult::Usage; }
            int v = 0;
            if (!textutil::parseInt(argv[i], v) || v <= 0) {
                error = "--time must be a positive number of seconds";
                return ParseResult::Usage;
            }
            opts.timeSeconds = v;
            haveTime = true;
        } else if (a == "--size") {
            if (++i >= argc) { error = "--size needs a value"; return ParseResult::Usage; }
            int v = 0;
            // Same range as the window's ping-size spin box.
            if (!textutil::parseInt(argv[i], v) || v < 64 || v > 8192) {
                error = "--size must be between 64 and 8192";
                return ParseResult::Usage;
            }
            opts.pingSize = static_cast<unsigned>(v);
        } else if (a == "--output") {
            if (++i >= argc) { error = "--output needs a path"; return ParseResult::Usage; }
            opts.outputPath = argv[i];
        } else if (a == "-4") {
            opts.ipVersion = 4;
        } else if (a == "-6") {
            opts.ipVersion = 6;
        } else if (a == "--json" || a == "--csv" || a == "--txt") {
            if (haveFormat) {
                error = "--txt, --json and --csv are mutually exclusive";
                return ParseResult::Usage;
            }
            opts.format = (a == "--json") ? OutputFormat::Json
                        : (a == "--csv")  ? OutputFormat::Csv
                                          : OutputFormat::Text;
            haveFormat = true;
        } else if (!a.empty() && a[0] == '-') {
            error = "Unknown option: " + a;
            return ParseResult::Usage;
        } else {
            if (!opts.target.empty()) { error = "Only one target may be given"; return ParseResult::Usage; }
            opts.target = a;
        }
    }

    if (!haveTime)            { error = "--time <seconds> is required"; return ParseResult::Usage; }
    if (opts.target.empty())  { error = "A target is required";         return ParseResult::Usage; }
    return ParseResult::Run;
}

int cli::printVersion()
{
    writeText(stdout, openMtrVersionLine() + "\n");
    return ExitOk;
}

int cli::run(int argc, char** argv)
{
    // See the comment on g_openMtrHeadless in tracer.h: this must be set
    // before DoTrace() can possibly be called below.
    g_openMtrHeadless.store(true);

#ifdef _WIN32
    // main()'s argv is in the ANSI code page, which cannot hold every name
    // or path; take the command line as UTF-16 and convert it to UTF-8.
    std::vector<std::string> utf8Args;
    std::vector<char*>       utf8Argv;
    if (int wargc = 0; LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc)) {
        for (int i = 0; i < wargc; ++i)
            utf8Args.push_back(utf8FromWide(wargv[i]));
        LocalFree(wargv);
        for (std::string& a : utf8Args)
            utf8Argv.push_back(a.data());
        utf8Argv.push_back(nullptr);
        argc = static_cast<int>(utf8Args.size());
        argv = utf8Argv.data();
    }
#endif

    setProgramName(argc > 0 ? argv[0] : nullptr);

    Options     opts;
    std::string error;
    switch (parseArgs(argc, argv, opts, error)) {
    case ParseResult::Usage:
        std::fprintf(stderr, "%s\n", error.c_str());
        printUsage(stderr);
        return ExitUsage;
    case ParseResult::Help:
        printUsage(stdout);
        return ExitOk;
    case ParseResult::Run:
        break;
    }

    SOCKADDR_INET addr = {};
    bool ipv6 = false;
    if (!resolveTarget(opts.target, opts.ipVersion == 4 ? AF_INET : AF_INET6, addr, ipv6)) {
        std::fprintf(stderr, "Could not resolve \"%s\".\n", opts.target.c_str());
        return ExitResolve;
    }

#if OPENMTR_ENABLE_UPDATE_CHECK
    // Same check, same blocking function, same GitHub endpoint as the GUI's
    // toolbar badge (see checkForUpdates() in MainWindow.cpp and
    // updatecheck.h/.cpp) — run here on a background thread so it can never
    // delay the trace itself, with its result printed to stderr whenever it
    // arrives. Left commented out of the CLI's behaviour entirely (like the
    // GUI) by OPENMTR_ENABLE_UPDATE_CHECK defaulting to 0 in CMakeLists.txt.
    std::thread([]() {
        const UpdateInfo info = checkForUpdateBlocking();
        if (info.available)
            std::fprintf(stderr, "\nA newer OpenMTR is available: %s\n%s\n\n",
                         info.version.toUtf8().constData(), info.url.toUtf8().constData());
    }).detach();
#endif // OPENMTR_ENABLE_UPDATE_CHECK

    std::atomic<bool>& interrupted = g_interrupted;
    interrupted.store(false);
    std::stop_source  stopSource;
#ifdef _WIN32
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
#else
    std::signal(SIGINT, sigintHandler);
#endif

    CliOptionsProvider  provider(opts.pingSize);
    OpenMTRNetWrapper    net(&provider);
    if (net.DoTrace(stopSource.get_token(), addr) != 0) {
        // An empty text means DoTrace() already reported the failure itself
        // (see OpenMTRNetWrapper::DoTrace in tracer.h).
        if (!net.lastErrorText().empty())
            std::fprintf(stderr, "%s\n", net.lastErrorText().c_str());
        return ExitEngine;
    }

    using Clock = std::chrono::steady_clock;
    const auto start = Clock::now();
    auto elapsedMs = [&]() -> int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
    };

    AsnCache asnCache;
    const auto asnLookup = [&](const std::string& ip, bool v6) { return asnCache.get(ip, v6); };
    Progress progress(stderrIsInteractive());

    // --- Phase 1: route discovery / warm-up ---------------------------
    // Same conditions as MainWindow::onWarmupEnd(), just driven by a
    // blocking sleep instead of QTimer::singleShot chaining.
    WarmupFingerprint fp;
    for (;;) {
        if (interrupted.load()) break;
        const int maxHops   = net.GetMax();
        const auto state    = net.getCurrentState();
        const int checkHops = std::min(maxHops, static_cast<int>(state.size()));
        // Warm the ASN cache as addresses appear, same as the GUI, so
        // lookups run concurrently with route discovery.
        for (const auto& h : state)
            if (h.addr.Ipv4.sin_family != AF_UNSPEC)
                asnCache.get(addr_to_string(h.addr), h.addr.Ipv6.sin6_family == AF_INET6);
        progress.update("Discovering route... (" + std::to_string(elapsedMs() / 1000) + "s)");
        if (warmupRouteSettled(fp, state, checkHops, elapsedMs()))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    if (!interrupted.load()) {
        // Same fixed settle pause the GUI gives itself before polling
        // ASN/reverse-DNS (see onWarmupEnd()'s QTimer::singleShot(400, ...)).
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        DnsSettle dns;
        for (;;) {
            if (interrupted.load()) break;
            const auto state = net.getCurrentState();
            progress.update("Resolving hostnames/ASN...");
            if (dnsAndAsnSettled(dns, state, asnCache.hasPending(), elapsedMs()))
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
    }

    // --- Phase 2: counting window ---------------------------------------
    ReportClock::time_point testStarted = ReportClock::now();
    int64_t countingStartMs = elapsedMs();
    if (!interrupted.load()) {
        net.resetStats();
        testStarted     = ReportClock::now();
        countingStartMs = elapsedMs();
        const int64_t deadlineMs = countingStartMs + static_cast<int64_t>(opts.timeSeconds) * 1000;
        while (!interrupted.load() && elapsedMs() < deadlineMs) {
            const int64_t remaining = (deadlineMs - elapsedMs() + 999) / 1000;   // round up
            progress.update("Measuring... " + std::to_string(std::max<int64_t>(remaining, 0)) + "s remaining");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    // Duration is measured against the counting window itself, ending here —
    // not against however long the engine then takes below to gracefully
    // wind down probes already in flight (one can take up to its own
    // timeout to notice the stop request). Computing it after that wait
    // instead would silently inflate the reported duration past what was
    // actually asked for with --time.
    int64_t durationMs = elapsedMs() - countingStartMs;
    if (durationMs < 0) durationMs = 0;

    progress.update("Finishing...");
    stopSource.request_stop();
    while (!net.isDone())
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    const auto finalState = net.getCurrentState();
    const auto rows       = computeReportRows(finalState, asnLookup);

    std::string report;
    switch (opts.format) {
        case OutputFormat::Json: report = buildJsonReport(opts.target, testStarted, durationMs, rows, finalState); break;
        case OutputFormat::Csv:  report = buildCsvReport(rows); break;
        case OutputFormat::Text: report = buildTextReport(opts.target, testStarted, durationMs, rows, finalState, ipv6); break;
    }

    // Clear the progress line before writing to stdout — otherwise, on a
    // real terminal, the report's first line would visually run on right
    // after "Finishing..." on the same row (stdout and stderr share the
    // screen but not a cursor position, so nothing else would separate
    // them).
    progress.finish();
    if (!opts.outputPath.empty()) {
        if (const int err = writeReportFile(opts.outputPath, report)) {
            std::fprintf(stderr, "Could not write \"%s\": %s\n",
                         opts.outputPath.c_str(), errnoText(err).c_str());
            return ExitOutputError;
        }
        // Otherwise there is no visible sign the run ever finished: no
        // stdout output at all in this branch, and nothing was printed
        // since the last progress update was cleared.
        std::fprintf(stderr, "Report written to %s (%lld bytes).\n",
                     opts.outputPath.c_str(), static_cast<long long>(report.size()));
    } else {
        std::string out = report;
        if (out.empty() || out.back() != '\n') out += '\n';
        writeText(stdout, out);
        std::fflush(stdout);
    }

    if (interrupted.load())
        return ExitInterrupted;

    // Reached: the resolved destination address appeared among the hops
    // that actually answered at least once during the run.
    const std::string destStr = addr_to_string(addr);
    bool reached = false;
    for (const auto& h : finalState) {
        if (h.addr.Ipv4.sin_family == AF_UNSPEC) continue;
        if (addr_to_string(h.addr) == destStr) {
            reached = true;
            break;
        }
    }
    return reached ? ExitOk : ExitNoReply;
}
