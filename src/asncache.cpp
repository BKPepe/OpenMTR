#include "asncache.h"

#include <system_error>
#include <thread>
#include <utility>

AsnCache::AsnCache(LookupFn lookup)
    : m_shared(std::make_shared<Shared>())
{
    m_shared->lookup = lookup ? lookup : lookupAsn;
}

// Cached ASN for an IP. Returns "-" immediately; on the first request it
// resolves in the background and fills the cache for next time. The
// background thread writes its result under a plain mutex rather than
// marshalling back through qApp, so this works with no Qt event loop
// running at all (the CLI report mode) as well as from the GUI.
std::string AsnCache::get(const std::string& ip, bool ipv6) const
{
    std::shared_ptr<Shared> shared = m_shared;
    {
        std::lock_guard<std::mutex> lock(shared->mutex);
        const auto it = shared->cache.find(ip);
        if (it != shared->cache.end())
            return it->second.empty() ? "-" : it->second;
        // Nothing to ask Team Cymru (private, link-local, ...): settled now,
        // without a thread.
        if (isUnroutableForAsn(ip)) {
            shared->cache[ip] = std::string();
            return "-";
        }
        if (!shared->pending.emplace(ip, Clock::now()).second)
            return "-";   // already resolving (or given up waiting for)
    }

    try {
        std::thread([shared, ip, ipv6]() {
            std::string asn = shared->lookup(ip, ipv6);
            std::lock_guard<std::mutex> lock(shared->mutex);
            shared->cache[ip] = std::move(asn);
            shared->pending.erase(ip);
        }).detach();
    } catch (const std::system_error&) {
        // No thread for it: settle the lookup as "no ASN" instead of
        // leaving it pending.
        std::lock_guard<std::mutex> lock(shared->mutex);
        shared->cache[ip] = std::string();
        shared->pending.erase(ip);
    }
    return "-";
}

void AsnCache::clear()
{
    std::lock_guard<std::mutex> lock(m_shared->mutex);
    m_shared->cache.clear();
    m_shared->pending.clear();
}

void AsnCache::clearPending()
{
    std::lock_guard<std::mutex> lock(m_shared->mutex);
    m_shared->pending.clear();
}

bool AsnCache::hasPending() const
{
    const Clock::time_point now = Clock::now();
    std::lock_guard<std::mutex> lock(m_shared->mutex);
    for (const auto& [ip, since] : m_shared->pending)
        if (now - since < kPendingTimeout)
            return true;
    return false;
}
