// Fuzz target: locator-directory codec (lib/mesh/locator_dir).
//
// REGISTER/QUERY/REPLY arrive as opaque payload in PKT_LOC packets straight
// off the radio. loc_parse must survive arbitrary bytes; accepted messages
// must rebuild + reparse identically.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "locator_dir.h"

using namespace mesh;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 2048) return 0;

    LocMsg m;
    if (!loc_parse(data, (uint16_t)size, &m)) return 0;

    uint8_t buf[512];
    uint16_t n = 0;
    switch (m.kind) {
        case LOC_REGISTER:
            n = loc_build_register(m.epoch, m.seq, m.ttl_s, m.id, m.id_len,
                                   buf, sizeof(buf));
            break;
        case LOC_QUERY:
            n = loc_build_query(m.qid, m.id, m.id_len, buf, sizeof(buf));
            break;
        case LOC_REPLY:
            n = loc_build_reply(m.qid, m.epoch, m.seq, m.ttl_s, m.loc, m.id,
                                m.id_len, buf, sizeof(buf));
            break;
        default:
            __builtin_trap();   // parse returned true for an unknown kind
    }
    if (n == 0) __builtin_trap();
    LocMsg m2;
    if (!loc_parse(buf, n, &m2)) __builtin_trap();
    if (m2.kind != m.kind || m2.id_len != m.id_len ||
        memcmp(m2.id, m.id, m.id_len) != 0) __builtin_trap();
    return 0;
}
