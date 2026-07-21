// Fuzz target: telemetry codec (lib/mesh/telemetry).
//
// BATT floods and STATUS query/reply arrive unauthenticated off the radio;
// telem_parse must survive arbitrary bytes, and anything it accepts must
// survive a rebuild round-trip.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "telemetry.h"

using namespace mesh;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 2048) return 0;

    TelemMsg m;
    if (!telem_parse(data, (uint16_t)size, &m)) return 0;

    // Round-trip whatever was accepted.
    uint8_t buf[1024];
    uint16_t n = 0;
    switch (m.kind) {
        case TELEM_BATT:
            n = telem_build_batt(m.mv, m.pct_plus1, buf, sizeof(buf));
            break;
        case TELEM_QUERY:
            n = telem_build_query(m.target, buf, sizeof(buf));
            break;
        case TELEM_REPLY:
            n = telem_build_reply(m.mv, m.pct_plus1, m.uptime_min, m.power_dbm,
                                  m.sf, m.flags, m.fw, m.name, m.nbrs, m.n_nbrs,
                                  buf, sizeof(buf));
            break;
    }
    if (n == 0) __builtin_trap();   // parser accepted what the builder rejects
    TelemMsg m2;
    if (!telem_parse(buf, n, &m2)) __builtin_trap();
    if (m2.kind != m.kind || m2.n_nbrs != m.n_nbrs) __builtin_trap();
    return 0;
}
