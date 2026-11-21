// ==========================================================================
//  fuzz_icmp.cpp — libFuzzer target for src/icmp_parse.h
//
//  The receive-path parsers read packets from anyone on the network, as
//  root in raw-socket mode, so they get fuzzed: build with
//  -DOPENMTR_BUILD_FUZZERS=ON (clang only), then e.g.
//
//    build/tests/fuzz_icmp -max_total_time=60
//
//  The first input byte picks the parser options, the next two the echo
//  identifier; the rest is the packet.
// ==========================================================================

#include "icmp_parse.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 3)
        return 0;
    const uint8_t  flags  = data[0];
    const uint16_t echoId = static_cast<uint16_t>(data[1] | (data[2] << 8));
    data += 3;
    size -= 3;
    const icmpparse::Match m4 = icmpparse::parseIcmp4(data, size, flags & 1, flags & 2, echoId);
    const icmpparse::Match m6 = icmpparse::parseIcmp6(data, size, flags & 2, echoId);
    // A match always has an answer type; touch the results so nothing is
    // optimized away.
    return (m4.valid && m4.seq == 0xFFFF && m6.valid) ? 0 : 0;
}
