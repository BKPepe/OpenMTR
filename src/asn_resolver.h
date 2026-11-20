// ==========================================================================
//  asn_resolver.h — Team Cymru ASN lookups through the system resolver
//
//  An address's origin AS comes from Team Cymru's DNS service: a TXT query
//  for the reversed address under origin.asn.cymru.com (origin6 for IPv6)
//  answers "15169 | 8.8.8.0/24 | US | arin | 2023-12-28". The query goes
//  through the operating system's own resolver API — the BIND resolver
//  functions of the C library (res_query + ns_initparse/ns_parserr; the
//  reentrant res_n* variants on macOS), DnsQuery_W on Windows — the way mtr
//  does it, so it uses the system's DNS configuration and cache (on OpenWrt,
//  dnsmasq) and needs no external program. It used to run `dig` through
//  QProcess on Linux and macOS, which most Linux installs and every OpenWrt
//  image lack, leaving the ASN column empty.
//
//  The parsing steps are pure functions, so tests/asn_parse_tests.cpp
//  checks them against hand-made DNS answers without any network.
// ==========================================================================

#pragma once

#include <string>
#include <string_view>

// True for addresses Team Cymru cannot answer for (private, loopback,
// link-local, CGNAT, unspecified, and anything that is not an address), so
// no query is made for them.
bool isUnroutableForAsn(const std::string& ip);

// The query name for `ip`: "4.3.2.1.origin.asn.cymru.com" for 1.2.3.4, the
// 32 nibbles of an IPv6 address in reverse order under origin6.asn.cymru.com.
// Empty when `ip` is not an address of that family.
std::string asnQueryName(const std::string& ip, bool ipv6);

// The ASN in one of Team Cymru's TXT strings: the first '|'-separated field,
// trimmed — "15169", or "23028 1234" for a prefix announced by two ASes.
// Empty for "0" (not announced), for an empty field, and for one that holds
// anything but numbers and spaces.
std::string asnFromTxt(std::string_view txt);

#ifndef _WIN32
// The ASN in a DNS answer message in wire format, as res_query() returns
// it: asnFromTxt() of the first character-string of the first well-formed
// TXT record in the answer section. Empty when there is none.
std::string asnFromDnsAnswer(const unsigned char* answer, int length);
#endif

// Resolves `ip`'s ASN. Blocking (one DNS round trip, longer when the
// resolver retries), so callers run it off their own thread — see AsnCache.
// Empty when the address is unroutable, the query fails or nothing is
// announced.
std::string lookupAsn(const std::string& ip, bool ipv6);
