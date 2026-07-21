// Fuzz target: KISS console framing (lib/mesh/kiss.h).
//
// The KISS decoder eats every byte typed or piped at the USB console, so it
// must survive arbitrary streams. Invariant checked: any frame the decoder
// yields, when re-encoded and re-decoded, comes back identical.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "kiss.h"

using namespace mesh;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static KissDecoder d;      // off-stack (holds an 801-byte buffer)
    d = KissDecoder{};         // fresh state per input (reproducible crashes)

    static uint8_t enc[2 * KISS_MAX_FRAME + 4];
    static KissDecoder d2;

    for (size_t i = 0; i < size; i++) {
        if (!d.feed(data[i])) continue;

        uint16_t flen = d.len();
        if (flen == 0 || flen > KISS_MAX_FRAME) __builtin_trap();

        // Round-trip: encode cmd+payload, feed through a fresh decoder,
        // require the identical frame back.
        uint8_t cmd = d.frame()[0];
        uint16_t n = kiss_encode(cmd, d.frame() + 1, (uint16_t)(flen - 1),
                                 enc, sizeof(enc));
        if (n == 0) __builtin_trap();   // cap covers worst-case expansion

        d2 = KissDecoder{};
        bool got = false;
        for (uint16_t k = 0; k < n; k++) got = d2.feed(enc[k]) || got;
        if (!got) __builtin_trap();
        if (d2.len() != flen || memcmp(d2.frame(), d.frame(), flen) != 0)
            __builtin_trap();
    }
    return 0;
}
