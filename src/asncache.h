// ==========================================================================
//  asncache.h — background ASN lookups + thread-safe cache (GUI + CLI)
//
//  AsnCache wraps lookupAsn() (asn_resolver.h) with a background thread per
//  lookup and a mutex-guarded cache: no qApp, no Qt event loop,
//  so the exact same cache class works whether the caller is MainWindow
//  (polled by a QTimer) or the CLI report mode (polled by a blocking sleep
//  loop, no QApplication at all).
// ==========================================================================

#pragma once

#include "asn_resolver.h"

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

// Cached ASN lookups with background resolution. get() returns the cached
// value immediately ("-" while unknown/pending) and, on the first request
// for a given IP, kicks off a detached background thread to resolve it —
// the next call for that IP (once resolved) returns the real value.
//
// Copyable/shareable by design: the actual cache lives in a shared_ptr'd
// block, so a background thread started by one copy always has somewhere
// safe to write even if the AsnCache that started it has since gone out of
// scope (mirrors the m_net shared_ptr pattern already used elsewhere).
class AsnCache {
public:
    // How long a lookup counts as pending. On Linux and macOS it used to be
    // bounded by `dig`'s 2 s timeout; the system resolver has its own,
    // longer ones (5 s per try and server by default), so without this bound
    // a resolver that never answers TXT queries (a blocked port, a broken
    // forwarder) would hold the warm-up's ASN/DNS grace window for as long
    // as those last. An answer that comes later still fills the cache.
    static constexpr std::chrono::milliseconds kPendingTimeout{2000};

    // `lookup` resolves one address; tests pass a stand-in for lookupAsn().
    using LookupFn = std::string (*)(const std::string& ip, bool ipv6);
    explicit AsnCache(LookupFn lookup = lookupAsn);

    std::string get(const std::string& ip, bool ipv6) const;
    // Clears both the resolved cache and the pending set — for a fresh
    // trace whose route may not overlap the previous one at all.
    void clear();
    // Clears only the pending set, keeping resolved values. Used after the
    // warm-up's ASN/DNS grace window ends: any lookup still in flight at
    // that point keeps running in its detached thread and will still fill
    // the cache when it completes, but dropping its "pending" bookkeeping
    // now means a later get() for that same IP (e.g. the next table
    // refresh) retries instead of being stuck treating it as forever
    // pending.
    void clearPending();
    // True while a lookup started less than kPendingTimeout ago is
    // unanswered.
    bool hasPending() const;

private:
    using Clock = std::chrono::steady_clock;
    struct Shared {
        mutable std::mutex                                 mutex;
        std::unordered_map<std::string, std::string>       cache;     // "" = no ASN
        std::unordered_map<std::string, Clock::time_point> pending;   // resolving, since
        LookupFn                                           lookup = nullptr;
    };
    std::shared_ptr<Shared> m_shared;
};
