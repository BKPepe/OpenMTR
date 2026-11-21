// ==========================================================================
//  report_core.h — shared report logic (GUI + CLI)
//
//  Everything here is deliberately free of QWidget/QTableWidget — and of Qt
//  altogether: it is the single source of truth for "what a hop's report
//  row looks like", "when has the route settled enough to start counting"
//  and "how a report renders as text/JSON/CSV". MainWindow (the GUI) and
//  cli.cpp (headless `--report` mode) both call into this instead of each
//  having their own copy, specifically so the two can never drift apart.
//  Text is UTF-8 std::string throughout; MainWindow converts at its edge.
// ==========================================================================

#pragma once

#include "tracer.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// ==========================================================================
//  Columns
// ==========================================================================

// Logical report/table columns. The two trailing spacer columns the GUI adds
// (ColCount and ColCount + 1) are a MainWindow-only rendering detail, not
// part of the report itself. Must stay in sync with kColumns.
enum Column {
    ColHop = 0, ColAsn, ColHostname, ColIp, ColLoss, ColSent, ColRecv,
    ColBest, ColAvrg, ColWrst, ColLast, ColJttr,
    ColCount
};

// Column headers, in Column order: the table's header row and the first
// line of a CSV export.
inline constexpr std::array<std::string_view, ColCount> kColumns = {
    "Hop", "ASN", "Hostname", "IP", "Loss %", "Sent", "Recv",
    "Best ms", "Avrg ms", "Wrst ms", "Last ms", "Jttr ms"
};

// ==========================================================================
//  Per-hop report row
// ==========================================================================

// One hop's already-formatted cell text (valid UTF-8), exactly as it should
// be displayed or exported — dashes for "no data yet", merged error text
// for a hop that never got an address. `errorRow` mirrors the GUI's
// merged-cell case: no address, but the engine has status text to show
// instead.
struct ReportRow {
    std::array<std::string, ColCount> cells;
    bool                              errorRow = false;
};

// A lookup callback: given an IP and whether it's v6, return its ASN (or
// "-" while still resolving/unknown). MainWindow and cli.cpp each pass
// their own AsnCache (see asncache.h) — same shape, different cache.
using AsnLookupFn = std::function<std::string(const std::string& ip, bool ipv6)>;

// Turns a raw engine snapshot into display-ready rows: hop numbering,
// address/name fallback, the merged "-" rules, loss percent, and RTT/jitter
// columns. Host names are repaired to valid UTF-8 here, once, for every
// consumer. Used by MainWindow::updateTable() to paint the results table and
// by the CLI report builder, so both show identical figures for identical
// engine state.
std::vector<ReportRow> computeReportRows(const std::vector<OpenMTRHostInfo>& state,
                                         const AsnLookupFn& asnLookup);

// A probe's status for the tooltip and the export: the engine's own
// sentence plus the numeric code, e.g. "Destination host unreachable,
// code 11003".
std::string describeStatus(unsigned long status, bool ipv6);

// Format a duration as H:MM:SS (or M:SS under an hour). Shared by the
// window-title elapsed display and every report's Duration field, so
// they never disagree on formatting.
std::string formatDuration(int64_t ms);

// ==========================================================================
//  Text / JSON / CSV export
// ==========================================================================

// Report time stamps are wall-clock times, shown in local time. An unset
// `testStarted` (no test was counted) is shown as the current time.
using ReportClock = std::chrono::system_clock;

// Renders a fixed-width ASCII box report, identical in content and layout
// to MainWindow's Export/Copy output.
std::string buildTextReport(const std::string& target,
                            std::optional<ReportClock::time_point> testStarted,
                            int64_t durationMs,
                            const std::vector<ReportRow>& rows,
                            const std::vector<OpenMTRHostInfo>& state,
                            bool traceIsV6);

// Renders the machine-readable JSON report: one object per hop, numbers as
// numbers, missing values ("-") as null. `generated` is the report's own
// time stamp, the current time unless given (the tests pin it).
std::string buildJsonReport(const std::string& target,
                            std::optional<ReportClock::time_point> testStarted,
                            int64_t durationMs,
                            const std::vector<ReportRow>& rows,
                            const std::vector<OpenMTRHostInfo>& state,
                            std::optional<ReportClock::time_point> generated = std::nullopt);

// Renders the report as CSV: header row from kColumns, one data row per hop.
// Same formula-injection guard and quoting as the GUI's Export dialog.
std::string buildCsvReport(const std::vector<ReportRow>& rows);

// ==========================================================================
//  Warm-up settling (route discovery, then ASN/reverse-DNS grace)
// ==========================================================================

// Route-fingerprint stability tracker (MainWindow's m_warmupFp), pulled out
// so a blocking CLI loop can drive the same state machine as the GUI's
// QTimer-chained one.
struct WarmupFingerprint {
    std::string fingerprint;
    int         stableCount = 0;
};

// True once the discovered route has held steady for the required number of
// ticks (or the deadline was reached) AND every checked hop has either
// answered or exhausted its two-timeout guard. False means "call again
// shortly" (every ~250 ms, same cadence as the GUI). `elapsedMs` is time
// since the trace started (m_elapsed in the GUI).
bool warmupRouteSettled(WarmupFingerprint& fp,
                        const std::vector<OpenMTRHostInfo>& state,
                        int checkHops,
                        int64_t elapsedMs);

// Reverse-DNS settling tracker for the post-route-settle grace window.
// Mirrors the GUI's dnsSeen/dnsStall pair in onWarmupEnd()'s ASN/DNS poll.
struct DnsSettle {
    int dnsSeen  = -1;
    int dnsStall = 0;
};

// True once every addressed hop has a resolved name (or reverse-DNS has
// stalled for a few ticks with nothing new arriving) AND no ASN lookup is
// still pending. `elapsedMs` is the same clock as warmupRouteSettled's,
// still counted from trace start — matches the GUI's single 16 s overall
// cap covering both phases.
bool dnsAndAsnSettled(DnsSettle& d,
                      const std::vector<OpenMTRHostInfo>& state,
                      bool asnPending,
                      int64_t elapsedMs);
