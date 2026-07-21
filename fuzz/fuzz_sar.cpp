// Fuzz target: SAR fragment ingest + reassembly (lib/mesh/sar) — STATEFUL.
//
// Reassembly is a state machine, so single-buffer fuzzing misses the
// interesting bugs (mixed transfers, inconsistent headers mid-transfer,
// overlapping fragments). The fuzz input is interpreted as a sequence of
// operations:
//
//   [op:u8][len:u8][payload:len bytes]  repeated
//
//   op % 8: 0-3 feed payload to SarReassembler::add   (weighted: most common)
//           4   sar_parse_nack(payload)
//           5   sar_parse_done(payload)
//           6   query missing()/complete()/verify()
//           7   reset()
#include <stddef.h>
#include <stdint.h>

#include "sar.h"

using namespace mesh;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 8192) return 0;

    SarReassembler r;
    size_t i = 0;
    while (i + 2 <= size) {
        uint8_t op = data[i] % 8;
        uint16_t len = data[i + 1];
        i += 2;
        if (len > size - i) len = (uint16_t)(size - i);
        const uint8_t* payload = data + i;
        i += len;

        switch (op) {
            default:   // 0-3: fragment ingest
                r.add(payload, len);
                break;
            case 4: {
                uint16_t xfer = 0, miss[64];
                uint16_t n = sar_parse_nack(payload, len, &xfer, miss, 64);
                if (n > 64) __builtin_trap();
                break;
            }
            case 5:
                sar_parse_done(payload, len);
                break;
            case 6: {
                uint16_t miss[SAR_MAX_FRAGS];
                uint16_t n = r.missing(miss, SAR_MAX_FRAGS);
                if (n > r.frag_count()) __builtin_trap();
                if (r.complete() && n != 0) __builtin_trap();
                r.verify();   // must be safe whatever state we're in
                if (r.got_count() > SAR_MAX_FRAGS) __builtin_trap();
                if (r.total_len() > SAR_MAX_FILE) __builtin_trap();
                break;
            }
            case 7:
                r.reset();
                break;
        }
    }
    return 0;
}
