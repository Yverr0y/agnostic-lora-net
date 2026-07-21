#include "announce_codec.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include <string.h>

namespace mesh {

// Domain tag for announce identity signatures (distinct from control's "AGN-CTRL-1").
static const uint8_t ANN_DOMAIN[9] = {'A','G','N','-','A','N','N','-','1'};
// Max announce body we sign/verify (a beacon body never approaches this on the wire); the
// lib stays independent of packet.h's MAX_PAYLOAD, so this is a self-contained bound.
static const uint16_t ANN_VIEW_BODY_MAX = 256;

// Build the signed view: DOMAIN || pubkey || announce-body. body_len is bounded by the
// LoRa payload, so a fixed stack buffer covers the worst case.
static uint16_t ann_view(const uint8_t pubkey[32], const uint8_t* body, uint16_t body_len,
                         uint8_t* out) {
    memcpy(out, ANN_DOMAIN, sizeof(ANN_DOMAIN));
    memcpy(out + sizeof(ANN_DOMAIN), pubkey, 32);
    memcpy(out + sizeof(ANN_DOMAIN) + 32, body, body_len);
    return (uint16_t)(sizeof(ANN_DOMAIN) + 32 + body_len);
}

// --- little-endian byte helpers --------------------------------------------
static inline void put_u8(uint8_t* p, uint8_t v)  { p[0] = v; }
static inline void put_u16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline uint8_t  get_u8(const uint8_t* p)  { return p[0]; }
static inline uint16_t get_u16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }

// --- quantisation ----------------------------------------------------------
static inline uint8_t q_to_byte(float q) {
    if (q < 0.0f) q = 0.0f;
    if (q > 1.0f) q = 1.0f;
    return (uint8_t)(q * 255.0f + 0.5f);
}
static inline float byte_to_q(uint8_t b) { return (float)b / 255.0f; }

static inline uint16_t cost_to_u16(float cost) {
    if (cost < 0.0f) cost = 0.0f;
    float v = cost * 16.0f + 0.5f;
    if (v > 65535.0f) v = 65535.0f;   // saturate
    return (uint16_t)v;
}
static inline float u16_to_cost(uint16_t v) { return (float)v / 16.0f; }

// ---------------------------------------------------------------------------
// A capability-aware node always emits the caps field (so peers learn it speaks
// the negotiated format); the field is omitted only when reconstructing a legacy
// announce that had none. `caps == 0` still emits the field when the flag is set
// — advertising "capability-aware, nothing extra yet" is distinct from "legacy".
uint16_t announce_serialize(const Announce& a, uint8_t* buf, uint16_t cap) {
    // Built announces default has_caps = true (caps-aware); the flag is only
    // false when re-serializing one decoded from a legacy frame, which keeps
    // decode->encode a faithful round-trip.
    const bool has_caps = a.has_caps;
    const uint16_t hdr = ANNOUNCE_HDR_BYTES + (has_caps ? ANNOUNCE_CAPS_BYTES : 0);
    if (cap < hdr) return 0;

    uint16_t off = hdr;                 // reserve header (counts [+ caps])
    uint8_t  n_reports = 0, n_routes = 0;

    for (uint8_t i = 0; i < a.n_reports; i++) {
        if (off + ANNOUNCE_REPORT_BYTES > cap) break;
        nid_write(buf + off, a.reports[i].id);  off += 16;
        put_u8 (buf + off, q_to_byte(a.reports[i].q)); off += 1;
        put_u8 (buf + off, a.reports[i].alias); off += 1;
        n_reports++;
    }
    for (uint8_t i = 0; i < a.n_routes; i++) {
        if (off + ANNOUNCE_ROUTE_BYTES > cap) break;
        nid_write(buf + off, a.routes[i].dst);      off += 16;
        nid_write(buf + off, a.routes[i].next_hop); off += 16;
        put_u16(buf + off, cost_to_u16(a.routes[i].cost)); off += 2;
        put_u8 (buf + off, a.routes[i].hops);     off += 1;
        n_routes++;
    }

    put_u8(buf + 0, (uint8_t)(n_reports | (has_caps ? ANNOUNCE_HAS_CAPS : 0)));
    put_u8(buf + 1, n_routes);
    if (has_caps) put_u16(buf + 2, a.caps);
    return off;
}

bool announce_deserialize(const uint8_t* buf, uint16_t len, Announce& out) {
    out = Announce{};
    if (len < ANNOUNCE_HDR_BYTES) return false;

    uint8_t  rep_byte = get_u8(buf + 0);
    bool     has_caps = (rep_byte & ANNOUNCE_HAS_CAPS) != 0;
    uint8_t  n_reports = rep_byte & (uint8_t)~ANNOUNCE_HAS_CAPS;   // low 7 bits
    uint8_t  n_routes  = get_u8(buf + 1);

    // Reject counts that can't fit our fixed arrays (untrusted radio input).
    // Note: a LEGACY decoder (no HAS_CAPS support) would see rep_byte >= 0x80 as
    // n_reports > MAX_NEIGHBORS here and reject — that's the intended clean
    // rejection of a caps announce by an old node.
    if (n_reports > MAX_NEIGHBORS || n_routes > MAX_ROUTES) return false;

    uint16_t hdr = ANNOUNCE_HDR_BYTES + (has_caps ? ANNOUNCE_CAPS_BYTES : 0);

    // Reject buffers too short for the declared payload.
    uint32_t need = (uint32_t)hdr
                  + (uint32_t)n_reports * ANNOUNCE_REPORT_BYTES
                  + (uint32_t)n_routes  * ANNOUNCE_ROUTE_BYTES;
    if (len < need) return false;

    out.has_caps = has_caps;
    out.caps = has_caps ? get_u16(buf + 2) : 0;   // unknown bits kept verbatim, ignored by callers

    uint16_t off = hdr;
    for (uint8_t i = 0; i < n_reports; i++) {
        out.reports[i].id    = nid_read(buf + off); off += 16;
        out.reports[i].q     = byte_to_q(get_u8(buf + off)); off += 1;
        out.reports[i].alias = get_u8(buf + off); off += 1;
    }
    out.n_reports = n_reports;

    for (uint8_t i = 0; i < n_routes; i++) {
        out.routes[i].dst      = nid_read(buf + off); off += 16;
        out.routes[i].next_hop = nid_read(buf + off); off += 16;
        out.routes[i].cost     = u16_to_cost(get_u16(buf + off)); off += 2;
        out.routes[i].hops     = get_u8(buf + off); off += 1;
    }
    out.n_routes = n_routes;
    return true;
}

uint16_t announce_body_len(const Announce& a) {
    // Mirrors the on-wire body: the caps field is present unless this announce
    // was decoded from a legacy (no-caps) frame. Built announces default
    // has_caps = true, so their serialized length matches.
    return (uint16_t)(ANNOUNCE_HDR_BYTES + (a.has_caps ? ANNOUNCE_CAPS_BYTES : 0)
                    + (uint16_t)a.n_reports * ANNOUNCE_REPORT_BYTES
                    + (uint16_t)a.n_routes  * ANNOUNCE_ROUTE_BYTES);
}

void announce_sign(const uint8_t* body, uint16_t body_len,
                   const uint8_t pubkey[32], const uint8_t seckey[64], uint8_t* tail) {
    if (body_len > ANN_VIEW_BODY_MAX) return;       // wire bodies never reach this
    memcpy(tail, pubkey, 32);
    // static (off-stack): the mesh runs single-threaded in one loop task, and this ~297-byte
    // buffer on the crypto path was overflowing that task's stack (see main.cpp agn_main_task).
    static uint8_t view[sizeof(ANN_DOMAIN) + 32 + ANN_VIEW_BODY_MAX];
    uint16_t vn = ann_view(pubkey, body, body_len, view);
    crypto_ed25519_sign(tail + 32, seckey, view, vn);
}

bool announce_verify(const uint8_t* body, uint16_t body_len,
                     const uint8_t* tail, uint8_t out_pubkey[32]) {
    if (body_len > ANN_VIEW_BODY_MAX) return false;
    const uint8_t* pubkey = tail;       // [0..32)
    const uint8_t* sig    = tail + 32;  // [32..96)
    static uint8_t view[sizeof(ANN_DOMAIN) + 32 + ANN_VIEW_BODY_MAX];  // off-stack (see announce_sign)
    uint16_t vn = ann_view(pubkey, body, body_len, view);
    if (crypto_ed25519_check(sig, pubkey, view, vn) != 0) return false;
    memcpy(out_pubkey, pubkey, 32);
    return true;
}

} // namespace mesh
