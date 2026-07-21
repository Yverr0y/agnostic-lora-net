// Fuzz target: signed control-plane codec (lib/mesh/control).
//
// ctrl_verify is the security boundary of the write path: it parses BEFORE the
// signature check, so the pre-verification parse must be safe on arbitrary
// bytes, and the verification path itself must not misbehave on garbage keys.
#include <stddef.h>
#include <stdint.h>

#include "control.h"

using namespace mesh;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 2048) return 0;

    // First 32 bytes = attacker-chosen "controller pubkey", rest = message.
    // (Garbage keys exercise the point-decompression failure paths too.)
    uint8_t pubkey[32] = {};
    const uint8_t* msg = data;
    size_t mlen = size;
    if (size >= 32) {
        for (int i = 0; i < 32; i++) pubkey[i] = data[i];
        msg = data + 32;
        mlen -= 32;
    }

    CtrlMsg m;
    ctrl_verify(msg, (uint16_t)mlen, pubkey, /*min_counter=*/0, &m);
    ctrl_verify(msg, (uint16_t)mlen, pubkey, /*min_counter=*/0xFFFFFFFFu, nullptr);

    CtrlAck a;
    if (ctrl_parse_ack(msg, (uint16_t)mlen, &a)) {
        // Round-trip: a parsed ACK must rebuild to an ACK that parses equal.
        uint8_t buf[CTRL_ACK_BYTES];
        if (ctrl_build_ack(a.cmd, a.origin, a.applied, a.provisional, a.counter,
                           buf, sizeof(buf)) != CTRL_ACK_BYTES) __builtin_trap();
        CtrlAck b;
        if (!ctrl_parse_ack(buf, CTRL_ACK_BYTES, &b)) __builtin_trap();
        if (b.cmd != a.cmd || b.counter != a.counter) __builtin_trap();
    }
    return 0;
}
