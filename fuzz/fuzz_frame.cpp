// Fuzz target: whole-frame RX dispatch — the paths that consume packet.h.
//
// Mirrors the firmware's on_rx() (src/main.cpp): parse LinkHeader/NetHeader
// off the raw frame, then route the payload to the per-type parser exactly the
// way the firmware does — beacon payload + announce body + signature tail for
// PKT_BEACON, ctrl_verify/ctrl_parse_ack for PKT_CONTROL, telem/loc parsers,
// and the SAR classifiers for PKT_DATA. This is the closest host-side
// approximation of "arbitrary bytes hit the radio".
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "packet.h"
#include "announce_codec.h"
#include "control.h"
#include "locator_dir.h"
#include "sar.h"
#include "telemetry.h"

using namespace mesh;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < HEADER_BYTES || size > 4096) return 0;
    const uint8_t* buf = data;
    uint16_t len = (uint16_t)size;

    NetHeader net;
    memcpy(&net, buf + sizeof(LinkHeader), sizeof(net));
    if (net_ver_of(net.ver_type) != PROTO_VERSION) return 0;

    const uint8_t* pay = buf + HEADER_BYTES;
    uint16_t plen = (uint16_t)(len - HEADER_BYTES);

    switch (net_type_of(net.ver_type)) {
        case PKT_BEACON: {
            const uint16_t base = HEADER_BYTES + (uint16_t)sizeof(BeaconPayload);
            Announce ann;
            bool ann_ok = false;
            if (len > base)
                ann_ok = announce_deserialize(buf + base, (uint16_t)(len - base), ann);
            if (ann_ok) {
                const uint8_t* region = buf + base;
                uint16_t region_len = (uint16_t)(len - base);
                uint16_t bl = announce_body_len(ann);
                if (region_len >= (uint16_t)(bl + ANNOUNCE_SIG_TAIL)) {
                    uint8_t pub[32];
                    announce_verify(region, bl, region + bl, pub);
                }
            }
            break;
        }
        case PKT_CONTROL: {
            static const uint8_t pubkey[32] = {0x42};
            if (ctrl_is_ack(pay, plen)) {
                CtrlAck a;
                ctrl_parse_ack(pay, plen, &a);
            } else {
                CtrlMsg m;
                ctrl_verify(pay, plen, pubkey, 0, &m);
            }
            break;
        }
        case PKT_TELEM: {
            TelemMsg m;
            telem_parse(pay, plen, &m);
            break;
        }
        case PKT_LOC: {
            LocMsg m;
            loc_parse(pay, plen, &m);
            break;
        }
        case PKT_DATA: {
            if (sar_is_fragment(pay, plen)) {
                static SarReassembler r;   // off-stack (8 KiB buffer)
                r.reset();
                r.add(pay, plen);
            } else if (sar_is_nack(pay, plen)) {
                uint16_t xfer = 0, miss[64];
                sar_parse_nack(pay, plen, &xfer, miss, 64);
            } else if (sar_is_done(pay, plen)) {
                sar_parse_done(pay, plen);
            }
            break;
        }
        default:
            break;
    }
    return 0;
}
