// Fuzz target: hop-by-hop ARQ engine (lib/mesh/link_arq) — STATEFUL.
//
// The ACK path is driven by attacker-controllable bytes (a forged link-layer
// ACK carries an arbitrary seq), and the retry engine is timer-driven. The
// fuzz input is a sequence of operations:
//
//   [op:u8][a:u8][b:u8]  repeated
//
//   op % 4: 0 track   (seq=a, frame = b bytes of pattern, timeout from a)
//           1 on_ack  (seq=a)
//           2 tick    (advance time by (a|b<<8) ms)
//           3 next_seq
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "link_arq.h"

using namespace mesh;

static uint32_t g_resends;

static void on_resend(void*, const uint8_t* frame, uint16_t len) {
    // Touch every byte so ASan sees any bad frame storage.
    uint32_t acc = 0;
    for (uint16_t i = 0; i < len; i++) acc += frame[i];
    (void)acc;
    g_resends++;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 4096) return 0;

    LinkArq arq;
    uint32_t now = 0;
    uint8_t frame[512];
    memset(frame, 0xA5, sizeof(frame));

    size_t i = 0;
    while (i + 3 <= size) {
        uint8_t op = data[i] % 4, a = data[i + 1], b = data[i + 2];
        i += 3;
        switch (op) {
            case 0: {
                // Deliberately allow len > ARQ_FRAME_MAX to exercise the reject path.
                uint16_t len = (uint16_t)(a | ((b & 1) << 8));
                node_id_t hop = nid_from_u32((uint32_t)b + 1);
                arq.track(a ? a : 1, hop, frame, len, now,
                          /*timeout_ms=*/(uint32_t)(b + 1) * 100,
                          /*max_retries=*/(uint8_t)(a % 7));
                break;
            }
            case 1:
                arq.on_ack(a);
                break;
            case 2:
                now += (uint32_t)(a | (b << 8));
                arq.tick(now, on_resend, nullptr);
                break;
            case 3:
                if (arq.next_seq() == 0) __builtin_trap();   // seq must skip 0
                break;
        }
        if (arq.pending_count() > ARQ_MAX_PENDING) __builtin_trap();
    }
    return 0;
}
