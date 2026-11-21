#include "report_core.h"
#include "textutil.h"

#include <jansson.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <memory>

using textutil::leftJustified;
using textutil::rightJustified;
using textutil::utf16Length;

// ==========================================================================
//  Status text / duration formatting
// ==========================================================================

std::string describeStatus(unsigned long status, bool ipv6)
{
    std::string text = OpenMTRStatusText(status, ipv6);
    if (!text.empty() && text.back() == '.')
        text.pop_back();
    return text + ", code " + std::to_string(status);
}

std::string formatDuration(int64_t ms)
{
    const int64_t secs = ms / 1000;
    const int h = static_cast<int>(secs / 3600), m = static_cast<int>((secs % 3600) / 60),
              s = static_cast<int>(secs % 60);
    char buf[32];
    if (h > 0)
        std::snprintf(buf, sizeof(buf), "%d:%02d:%02d", h, m, s);
    else
        std::snprintf(buf, sizeof(buf), "%d:%02d", m, s);
    return buf;
}

// ==========================================================================
//  Per-hop report row
// ==========================================================================

std::vector<ReportRow> computeReportRows(const std::vector<OpenMTRHostInfo>& state,
                                         const AsnLookupFn& asnLookup)
{
    std::vector<ReportRow> rows;
    rows.reserve(state.size());

    for (size_t i = 0; i < state.size(); ++i) {
        const auto& h = state[i];
        ReportRow row;

        const std::string ip = addr_to_string(h.addr);
        const bool hasAddr   = (h.addr.Ipv4.sin_family != AF_UNSPEC);
        // A reverse-DNS answer is raw bytes on POSIX; repaired once, here,
        // for the table and every report format (JSON needs valid UTF-8).
        std::string name = textutil::toValidUtf8(h.getName());
        if (hasAddr && name.empty()) name = ip;
        // Hops without an address show the engine's status text ("Request
        // timed out.", "Destination host unreachable.", ...) so active ICMP
        // refusals are visible instead of hiding behind a dash. Before the
        // first probe completes there is no status yet, hence the dash.
        if (!hasAddr && name.empty()) name = "-";

        row.errorRow = !hasAddr && name != "-";

        row.cells[ColHop]      = std::to_string(i + 1);
        row.cells[ColAsn]      = hasAddr ? asnLookup(ip, h.addr.Ipv6.sin6_family == AF_INET6) : "-";
        row.cells[ColHostname] = name;
        row.cells[ColIp]       = hasAddr ? ip : "-";

        if (h.xmit == 0) {
            for (int c = ColLoss; c < ColCount; ++c) row.cells[c] = "-";
        } else {
            const int loss = 100 - (100 * h.returned / h.xmit);
            row.cells[ColLoss] = std::to_string(loss);
            row.cells[ColSent] = std::to_string(h.xmit);
            row.cells[ColRecv] = std::to_string(h.returned);
            row.cells[ColBest] = h.returned == 0 ? "-" : std::to_string(h.best);
            row.cells[ColAvrg] = h.returned == 0 ? "-" : std::to_string(h.getAvg());
            row.cells[ColWrst] = h.returned == 0 ? "-" : std::to_string(h.worst);
            row.cells[ColLast] = h.returned == 0 ? "-" : std::to_string(h.last);
            row.cells[ColJttr] = h.returned < 2  ? "-" : std::to_string(h.getJitter());
        }

        rows.push_back(std::move(row));
    }
    return rows;
}

// ==========================================================================
//  Text / JSON / CSV export
// ==========================================================================

namespace {

std::time_t timeOf(std::optional<ReportClock::time_point> t)
{
    return ReportClock::to_time_t(t.value_or(ReportClock::now()));
}

// jansson takes its strings as valid UTF-8 (and refuses anything else);
// everything put into the report goes through here.
json_t* jsonString(const std::string& s)
{
    const std::string valid = textutil::toValidUtf8(s);
    return json_stringn(valid.data(), valid.size());
}

struct JsonDeleter {
    void operator()(json_t* j) const { json_decref(j); }
};

}  // namespace

std::string buildJsonReport(const std::string& target,
                            std::optional<ReportClock::time_point> testStarted,
                            int64_t durationMs,
                            const std::vector<ReportRow>& rows,
                            const std::vector<OpenMTRHostInfo>& state,
                            std::optional<ReportClock::time_point> generated)
{
    static const char* const keys[ColCount] = {
        "hop", "asn", "hostname", "ip", "loss", "sent", "recv",
        "best", "avrg", "wrst", "last", "jttr"
    };
    std::unique_ptr<json_t, JsonDeleter> root(json_object());
    json_t* hops = json_array();
    for (size_t i = 0; i < rows.size(); ++i) {
        const ReportRow& row = rows[i];
        json_t* o = json_object();
        for (int c = 0; c < ColCount; ++c) {
            const std::string& v = row.cells[c];
            // Missing values are null; anything QString::toInt() would take
            // for a number is one (the host name "1234" included, as ever).
            int n = 0;
            json_t* value = (v.empty() || v == "-") ? json_null()
                          : textutil::parseInt(v, n) ? json_integer(n)
                                                     : jsonString(v);
            json_object_set_new(o, keys[c], value);
        }
        if (i < state.size() && state[i].altCount > 0) {
            json_object_set_new(o, "alt_ip",    jsonString(addr_to_string(state[i].altAddr)));
            json_object_set_new(o, "alt_count", json_integer(state[i].altCount));
        }
        json_array_append_new(hops, o);
    }
    json_object_set_new(root.get(), "target",           jsonString(target));
    json_object_set_new(root.get(), "test_started",
                        jsonString(textutil::formatLocalTime(timeOf(testStarted), "%Y-%m-%dT%H:%M:%S")));
    json_object_set_new(root.get(), "duration_seconds", json_integer(durationMs / 1000));
    json_object_set_new(root.get(), "generated",
                        jsonString(textutil::formatLocalTime(timeOf(generated), "%Y-%m-%dT%H:%M:%S")));
    json_object_set_new(root.get(), "hops",             hops);

    // Four-space indentation and sorted keys: the layout QJsonDocument's
    // Indented format produced, so reports are byte-identical to the ones
    // OpenMTR wrote before it used jansson (tests/golden/).
    std::unique_ptr<char, decltype(&std::free)> text(
        json_dumps(root.get(), JSON_INDENT(4) | JSON_SORT_KEYS), &std::free);
    if (!text)
        return std::string();
    std::string out(text.get());
    // jansson writes the hex digits of a \u escape (only control characters
    // get one here) in upper case, QJsonDocument wrote them in lower case.
    // Both are valid JSON; keep the old bytes. Backslashes only occur in
    // escapes, so after one, the next character is always the escape's own.
    for (size_t i = 0; i + 1 < out.size(); ++i) {
        if (out[i] != '\\')
            continue;
        if (out[i + 1] == 'u')
            for (size_t k = i + 2; k < i + 6 && k < out.size(); ++k)
                if (out[k] >= 'A' && out[k] <= 'F')
                    out[k] = static_cast<char>(out[k] - 'A' + 'a');
        ++i;
    }
    out += '\n';
    return out;
}

std::string buildCsvReport(const std::vector<ReportRow>& rows)
{
    std::string out;
    for (int c = 0; c < ColCount; ++c) {
        if (c) out += ',';
        out += kColumns[c];
    }
    out += '\n';
    for (const auto& row : rows) {
        for (int c = 0; c < ColCount; ++c) {
            std::string val = row.cells[c];
            // Neutralise spreadsheet formula injection, but only in the
            // hostname column — the one place a remote party controls the
            // text: a hop along the path can name itself "=cmd|..." via
            // reverse DNS and Excel/LibreOffice would run the cell as a
            // formula when this CSV is opened. Risky leading characters get
            // the OWASP-recommended quote prefix. The other columns are
            // app-generated numbers, addresses and fixed strings, where
            // prefixing could only distort data.
            if (c == ColHostname && !val.empty() && val != "-") {
                const char c0 = val[0];
                if (c0 == '=' || c0 == '+' || c0 == '-' || c0 == '@' || c0 == '\t')
                    val.insert(val.begin(), '\'');
            }
            if (val.find_first_of(",\"") != std::string::npos) {
                std::string quoted = "\"";
                for (const char ch : val) {
                    if (ch == '"') quoted += '"';
                    quoted += ch;
                }
                val = quoted + "\"";
            }
            if (c) out += ',';
            out += val;
        }
        out += '\n';
    }
    return out;
}

std::string buildTextReport(const std::string& target,
                            std::optional<ReportClock::time_point> testStarted,
                            int64_t durationMs,
                            const std::vector<ReportRow>& rows,
                            const std::vector<OpenMTRHostInfo>& state,
                            bool traceIsV6)
{
    // Column widths in UTF-16 code units, as they have always been measured
    // (QString::length()): a host name with non-ASCII characters keeps
    // today's alignment.
    std::array<size_t, ColCount> W{};
    for (int c = 0; c < ColCount; ++c) {
        size_t w = utf16Length(kColumns[c]);
        for (const auto& row : rows)
            w = std::max(w, utf16Length(row.cells[c]));
        W[c] = w;
    }
    // Every column reads better right-aligned (numbers/percentages lining up
    // on their ones digit) except Hostname and IP, which are free-form text
    // of very different lengths — those stay left-aligned. Applies to the
    // header row too, so it lines up with the data underneath it.
    auto isRightAligned = [](int c) { return c != ColHostname && c != ColIp; };
    auto cell = [&](std::string_view s, int c) {
        return isRightAligned(c) ? rightJustified(s, W[c]) : leftJustified(s, W[c]);
    };
    std::string sep = "+";
    for (int c = 0; c < ColCount; ++c) sep += std::string(W[c] + 2, '-') + "+";
    std::string out;
    out += "OpenMTR Export\n";
    out += "Target  : " + textutil::toValidUtf8(target) + "\n";
    out += "Date    : " + textutil::formatLocalTime(timeOf(testStarted), "%Y-%m-%d %H:%M:%S") + "\n";
    out += "Duration: " + formatDuration(durationMs) + "\n\n";
    out += sep + "\n";
    std::string hdr = "|";
    for (int c = 0; c < ColCount; ++c) hdr += " " + cell(kColumns[c], c) + " |";
    out += hdr + "\n" + sep + "\n";
    for (const auto& row : rows) {
        std::string line = "|";
        for (int c = 0; c < ColCount; ++c) {
            if (row.errorRow && c == ColHostname) {
                // Error rows merge Hostname+IP into one left-aligned field
                // spanning the combined width of both columns — still text,
                // so it stays left-aligned like Hostname/IP normally would.
                const size_t wSpan = W[ColHostname] + W[ColIp] + 3;
                line += " " + leftJustified(row.cells[ColHostname], wSpan) + " |";
                ++c;   // the IP column is consumed by the span
                continue;
            }
            line += " " + cell(row.cells[c], c) + " |";
        }
        out += line + "\n";
    }
    out += sep + "\n";
    // Anomalous probe completions (a reply carrying an uncounted ICMP status,
    // or a soft failure of the send call) are invisible in the table but
    // matter when diagnosing unexplained single-packet losses — list them.
    {
        std::string notes;
        for (size_t i = 0; i < state.size(); ++i)
            if (state[i].altCount > 0)
                notes += "  Hop " + std::to_string(i + 1) + ": replies also arrived from "
                       + addr_to_string(state[i].altAddr) + " (" + std::to_string(state[i].altCount)
                       + " time(s)) \xE2\x80\x94 route change or per-packet load balancing\n";   // em dash
        for (size_t i = 0; i < state.size(); ++i)
            if (state[i].anomalyCount > 0)
                notes += "  Hop " + std::to_string(i + 1) + ": " + std::to_string(state[i].anomalyCount)
                       + " probe(s) ended with unexpected ICMP status/error: "
                       + describeStatus(state[i].anomalyLast, traceIsV6) + "\n";
        if (!notes.empty())
            out += "\nNotes:\n" + notes;
    }
    return out;
}

// ==========================================================================
//  Warm-up settling
// ==========================================================================

bool warmupRouteSettled(WarmupFingerprint& fp,
                        const std::vector<OpenMTRHostInfo>& state,
                        int checkHops,
                        int64_t elapsedMs)
{
    constexpr int64_t kWarmupDeadlineMs = 12000;
    // The route fingerprint (hop count plus every hop's address) must hold
    // steady for this many 250 ms ticks before we call it settled.
    // Responding hops probe on a ~1 s cycle, so the window spans one full
    // cycle with margin; silent hops (5 s timeout cycles) are covered by the
    // per-hop guard below rather than by this window.
    constexpr int kWarmupStableTicks = 5;
    const bool deadlineReached = elapsedMs >= kWarmupDeadlineMs;

    if (deadlineReached)
        return true;

    // Fingerprint the discovered route: hop count plus every hop's address.
    // Requiring the whole fingerprint — not just the count — to hold steady
    // also catches middle hops that are still filling in while the
    // destination has already answered. An undiscovered route (hop count
    // pinned at the ceiling) needs no special case: the fingerprint plus the
    // per-hop guard below settle it as well, so even an unreachable target
    // gets a complete, stable reveal. The deadline is only a backstop for
    // routes that never stop changing.
    std::string newFp;
    newFp += static_cast<char>(checkHops);
    for (int i = 0; i < checkHops; ++i) {
        const auto& a = state[i].addr;
        if (a.Ipv4.sin_family == AF_INET)
            newFp.append(reinterpret_cast<const char*>(&a.Ipv4.sin_addr),
                         sizeof(a.Ipv4.sin_addr));
        else if (a.Ipv6.sin6_family == AF_INET6)
            newFp.append(reinterpret_cast<const char*>(&a.Ipv6.sin6_addr),
                         sizeof(a.Ipv6.sin6_addr));
        else
            newFp += '\0';
    }
    // Any change to the route restarts the stability window.
    if (newFp != fp.fingerprint) {
        fp.fingerprint = newFp;
        fp.stableCount = 1;
        return false;
    }
    if (++fp.stableCount < kWarmupStableTicks)
        return false;

    // Every hop we are about to show must have either answered at least once
    // or sat through two full probe windows without answering. xmit
    // increments only after a probe completes, so for a silent hop
    // xmit >= 2 means two complete 5 s timeouts — it is almost certainly a
    // genuinely silent hop, not one whose first reply is still in flight and
    // would pop into the table right after the reveal.
    for (int i = 0; i < checkHops; ++i)
        if (state[i].returned == 0 && state[i].xmit < 2)
            return false;

    return true;
}

bool dnsAndAsnSettled(DnsSettle& d,
                      const std::vector<OpenMTRHostInfo>& state,
                      bool asnPending,
                      int64_t elapsedMs)
{
    // Consider reverse-DNS "settled" when every addressed hop shows a name
    // other than its bare IP, or when no new name has appeared for a few
    // ticks (the remaining hops simply have no PTR record). This never
    // blocks on a result that isn't coming.
    int addressed = 0, named = 0;
    for (const auto& h : state) {
        if (h.addr.Ipv4.sin_family == AF_UNSPEC) continue;
        ++addressed;
        if (h.getName() != addr_to_string(h.addr)) ++named;
    }
    bool dnsSettled;
    if (addressed == 0 || named >= addressed)  dnsSettled = true;
    else if (d.dnsSeen < 0)     { d.dnsSeen = named; d.dnsStall = 0; dnsSettled = false; }
    else if (named > d.dnsSeen) { d.dnsSeen = named; d.dnsStall = 0; dnsSettled = false; }
    else                          dnsSettled = (++d.dnsStall >= 3);   // ~450 ms without a new name

    if ((asnPending || !dnsSettled) && elapsedMs < 16000)
        return false;
    return true;
}
