// ==========================================================================
//  report_golden_tests.cpp — the report formats, byte for byte
//
//  Runs a fixed, synthetic engine snapshot through report_core's builders
//  (text, JSON, CSV — what Copy, Export and --report produce) and compares
//  the result with the files in tests/golden/. They are the contract for the
//  report format: a change to a builder that alters any byte of a report
//  fails here, and changing a golden file on purpose shows up in review as
//  exactly the bytes that change for users.
//
//    report_golden_tests check  <golden dir>   compare (what ctest runs)
//    report_golden_tests update <golden dir>   rewrite the golden files
//
//  The snapshot covers every kind of row the builders treat differently: a
//  plain hop, a hop with an alternate responder, one with anomalous probe
//  completions, an error row (no address, engine status text instead), a
//  hop with no data yet, a multi-origin ASN, an all-digit host name (typed
//  as a number in JSON), and a hostile host name with CSV/JSON
//  metacharacters, a control character, DEL and non-ASCII text. IPv6
//  addresses are written in canonical form only, so that every inet_ntop
//  (musl 1.2.5 and 1.2.6 differ for some non-canonical cases) agrees.
// ==========================================================================

#include "report_core.h"

#include <QtCore/QDate>
#include <QtCore/QDateTime>
#include <QtCore/QRegularExpression>
#include <QtCore/QTime>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

// Fixed clock: the test runs in UTC (main() sets TZ before anything reads
// the time zone), the trace "started" at kStarted, the report was
// "generated" at kGenerated. Until the builders take the generation time as
// a parameter it is the real current time, normalized to kGenerated below.
const char* const kGenerated = "2026-11-20T12:35:10";

SOCKADDR_INET v4(const char* text)
{
    SOCKADDR_INET a{};
    a.Ipv4.sin_family = AF_INET;
    inet_pton(AF_INET, text, &a.Ipv4.sin_addr);
    return a;
}

SOCKADDR_INET v6(const char* text)
{
    SOCKADDR_INET a{};
    a.Ipv6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, text, &a.Ipv6.sin6_addr);
    return a;
}

OpenMTRHostInfo hop(SOCKADDR_INET addr, const std::string& name, int xmit, int returned,
                    int best, int worst, int last, unsigned long total, unsigned long jitterSum)
{
    OpenMTRHostInfo h;
    h.addr      = addr;
    h.name      = name;
    h.xmit      = xmit;
    h.returned  = returned;
    h.best      = best;
    h.worst     = worst;
    h.last      = last;
    h.total     = total;
    h.jitterSum = jitterSum;
    return h;
}

std::vector<OpenMTRHostInfo> snapshotV4()
{
    std::vector<OpenMTRHostInfo> s;
    // 1: plain hop
    s.push_back(hop(v4("192.0.2.1"), "router.example", 10, 10, 1, 5, 2, 25, 9));
    // 2: replies also came from a second address
    {
        OpenMTRHostInfo h = hop(v4("198.51.100.7"), "edge-1.example", 10, 9, 8, 21, 9, 99, 30);
        h.altAddr  = v4("198.51.100.8");
        h.altCount = 3;
        s.push_back(h);
    }
    // 3: anomalous completions, no reverse name (shows the address)
    {
        OpenMTRHostInfo h = hop(v4("203.0.113.5"), "203.0.113.5", 10, 8, 11, 14, 12, 98, 7);
        h.anomalyCount = 2;
        h.anomalyLast  = IP_DEST_HOST_UNREACHABLE;
        s.push_back(h);
    }
    // 4: error row — never answered, the engine's status text instead
    s.push_back(hop(SOCKADDR_INET{}, "Request timed out.", 10, 0, 0, 0, 0, 0, 0));
    // 5: no data yet
    s.push_back(hop(SOCKADDR_INET{}, "", 0, 0, 0, 0, 0, 0, 0));
    // 6: multi-origin prefix: the ASN cell holds two numbers
    s.push_back(hop(v4("192.0.2.66"), "multi.example", 10, 10, 15, 19, 16, 161, 12));
    // 7: an all-digit name (JSON types it as a number)
    s.push_back(hop(v4("192.0.2.77"), "1234", 10, 1, 17, 17, 17, 17, 0));
    // 8: hostile name: formula prefix, CSV/JSON metacharacters, a slash,
    //    non-ASCII, TAB, a control character, DEL and U+2028
    s.push_back(hop(v4("198.51.100.99"),
                    "=cmd|' /c calc'!A0,\"q\" caf\xC3\xA9\tx\x1C\x7F\xE2\x80\xA8" "end",
                    10, 10, 20, 24, 21, 215, 18));
    // 9: the destination
    s.push_back(hop(v4("203.0.113.200"), "dest.example", 10, 10, 22, 30, 23, 239, 15));
    return s;
}

std::vector<OpenMTRHostInfo> snapshotV6()
{
    std::vector<OpenMTRHostInfo> s;
    s.push_back(hop(v6("2001:db8::1"), "gw6.example", 20, 20, 1, 3, 1, 30, 10));
    {
        OpenMTRHostInfo h = hop(v6("2001:db8:1::2"), "2001:db8:1::2", 20, 18, 9, 40, 12, 230, 51);
        h.altAddr      = v6("2001:db8:1::3");
        h.altCount     = 1;
        // IPv6 renders this status differently (administratively prohibited)
        h.anomalyCount = 1;
        h.anomalyLast  = IP_DEST_PROT_UNREACHABLE;
        s.push_back(h);
    }
    s.push_back(hop(v6("2001:db8:2::1"), "dest6.example", 20, 20, 30, 33, 31, 620, 20));
    return s;
}

QString asnFor(const QString& ip, bool /*ipv6*/)
{
    static const std::map<std::string, std::string> table = {
        { "192.0.2.1",     "64496" },
        { "198.51.100.7",  "64497" },
        { "192.0.2.66",    "23028 1234" },
        { "203.0.113.200", "64511" },
        { "2001:db8::1",   "64500" },
        { "2001:db8:2::1", "64501" },
    };
    const auto it = table.find(ip.toStdString());
    return it == table.end() ? QStringLiteral("-") : QString::fromStdString(it->second);
}

struct Scenario {
    std::string                  name;      // golden file stem
    std::string                  target;
    bool                         v6;
    qint64                       durationMs;
    std::vector<OpenMTRHostInfo> state;
};

std::map<std::string, std::string> render(const Scenario& sc)
{
    const QDateTime started(QDate(2026, 11, 20), QTime(12, 34, 56));
    const QString   target = QString::fromStdString(sc.target);
    const auto      rows   = computeReportRows(sc.state, asnFor);

    QString json = buildJsonReport(target, started, sc.durationMs, rows, sc.state);
    json.replace(QRegularExpression(QStringLiteral("\"generated\": \"[^\"]*\"")),
                 QStringLiteral("\"generated\": \"%1\"").arg(QLatin1String(kGenerated)));

    std::map<std::string, std::string> out;
    out[sc.name + ".txt"]  = buildTextReport(target, started, sc.durationMs, rows, sc.state, sc.v6).toStdString();
    out[sc.name + ".json"] = json.toStdString();
    out[sc.name + ".csv"]  = buildCsvReport(rows).toStdString();
    return out;
}

bool readFile(const std::string& path, std::string& data)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    data = ss.str();
    return true;
}

// Where two texts first differ, as "line N", for the failure message.
int firstDifferentLine(const std::string& a, const std::string& b)
{
    int line = 1;
    for (size_t i = 0; i < a.size() && i < b.size(); ++i) {
        if (a[i] != b[i])
            return line;
        if (a[i] == '\n')
            ++line;
    }
    return line;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 3 || (std::strcmp(argv[1], "check") != 0 && std::strcmp(argv[1], "update") != 0)) {
        std::fprintf(stderr, "usage: %s check|update <golden dir>\n", argv[0]);
        return 2;
    }
    const bool        update = std::strcmp(argv[1], "update") == 0;
    const std::string dir    = argv[2];

#ifdef _WIN32
    _putenv_s("TZ", "UTC");
    _tzset();
#else
    setenv("TZ", "UTC", 1);
    tzset();
#endif

    const std::vector<Scenario> scenarios = {
        { "report_v4", "dest.example", false, 61234,   snapshotV4() },
        { "report_v6", "dest6.example", true, 3725000, snapshotV6() },
    };

    int failures = 0;
    for (const Scenario& sc : scenarios) {
        for (const auto& [file, actual] : render(sc)) {
            const std::string path = dir + "/" + file;
            if (update) {
                std::ofstream out(path, std::ios::binary | std::ios::trunc);
                out << actual;
                std::printf("wrote %s\n", path.c_str());
                continue;
            }
            std::string expected;
            if (!readFile(path, expected)) {
                std::printf("FAIL %s: cannot read the golden file\n", path.c_str());
                ++failures;
            } else if (expected != actual) {
                std::printf("FAIL %s: differs from line %d on; actual output:\n%s\n",
                            path.c_str(), firstDifferentLine(expected, actual), actual.c_str());
                ++failures;
            }
        }
    }
    return failures ? 1 : 0;
}
