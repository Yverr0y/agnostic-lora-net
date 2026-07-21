// Fuzz target: announce wire codec (lib/mesh/announce_codec).
//
// Anyone can transmit at these nodes; announce_deserialize parses raw radio
// bytes, and announce_verify runs Ed25519 verification over attacker-shaped
// body/tail splits. Both must survive arbitrary input.
#include <stddef.h>
#include <stdint.h>

#include "announce_codec.h"

using namespace mesh;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 4096) return 0;   // wire bodies are < one LoRa frame; 4 KiB is generous

    Announce a;
    if (announce_deserialize(data, (uint16_t)size, a)) {
        // A parse that succeeded must re-serialize into a buffer of the size it
        // claims, and that must parse again (round-trip stability).
        uint8_t buf[4096];
        uint16_t n = announce_serialize(a, buf, sizeof(buf));
        if (n != announce_body_len(a)) __builtin_trap();
        Announce b;
        if (!announce_deserialize(buf, n, b)) __builtin_trap();
    }

    // Signature tail path: interpret the input's last 96 bytes as [pubkey][sig].
    if (size >= ANNOUNCE_SIG_TAIL) {
        uint8_t pub[32];
        announce_verify(data, (uint16_t)(size - ANNOUNCE_SIG_TAIL),
                        data + size - ANNOUNCE_SIG_TAIL, pub);
    }
    return 0;
}
