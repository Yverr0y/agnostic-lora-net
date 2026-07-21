// Host unit tests for the announce wire codec (lib/mesh/announce_codec).
//
//   pio test -e native
//
// Deserialisation parses untrusted bytes off the radio, so the malformed-input
// cases matter as much as the happy path.

#include <unity.h>
#include "announce_codec.h"
#include "capabilities.h"          // Capability bits, NODE_CAPS
#include "node_table.h"            // nid_from_pubkey
#include "monocypher.h"
#include "monocypher-ed25519.h"

using namespace mesh;

static Announce make_sample() {
    Announce a;
    a.origin = nid_from_u32(0x11111111u);
    a.reports[0] = {nid_from_u32(0xAAAAAAAAu), 0.80f, 3};
    a.reports[1] = {nid_from_u32(0xBBBBBBBBu), 0.20f, 7};
    a.n_reports = 2;
    a.routes[0] = {nid_from_u32(0xAAAAAAAAu), nid_from_u32(0xAAAAAAAAu), 1.5f, 1};
    a.routes[1] = {nid_from_u32(0xCCCCCCCCu), nid_from_u32(0xBBBBBBBBu), 3.25f, 2};
    a.n_routes = 2;
    return a;
}

// The full header this firmware emits: counts + the always-present caps field.
static constexpr uint16_t HDR = ANNOUNCE_HDR_BYTES + ANNOUNCE_CAPS_BYTES;

// Round-trip: fields survive serialise -> deserialise within quantisation error.
static void test_roundtrip() {
    Announce a = make_sample();
    a.caps = 0x0005;   // CAP_SELECTIVE_ACK | CAP_DICT_COMPRESS1 (arbitrary bits)
    uint8_t buf[256];
    uint16_t n = announce_serialize(a, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_UINT16(HDR + 2 * ANNOUNCE_REPORT_BYTES + 2 * ANNOUNCE_ROUTE_BYTES, n);

    Announce b;
    TEST_ASSERT_TRUE(announce_deserialize(buf, n, b));
    TEST_ASSERT_EQUAL_UINT8(2, b.n_reports);
    TEST_ASSERT_EQUAL_UINT8(2, b.n_routes);
    TEST_ASSERT_EQUAL_HEX16(0x0005, b.caps);   // capability bits survive the round-trip

    TEST_ASSERT_TRUE(b.reports[0].id == nid_from_u32(0xAAAAAAAAu));
    TEST_ASSERT_FLOAT_WITHIN(0.01f, 0.80f, b.reports[0].q);   // 1/255 quantisation
    TEST_ASSERT_FLOAT_WITHIN(0.01f, 0.20f, b.reports[1].q);
    TEST_ASSERT_EQUAL_UINT8(3, b.reports[0].alias);           // alias carried exactly
    TEST_ASSERT_EQUAL_UINT8(7, b.reports[1].alias);

    TEST_ASSERT_TRUE(b.routes[1].dst == nid_from_u32(0xCCCCCCCCu));
    TEST_ASSERT_TRUE(b.routes[1].next_hop == nid_from_u32(0xBBBBBBBBu));
    TEST_ASSERT_FLOAT_WITHIN(0.07f, 3.25f, b.routes[1].cost);  // 1/16 quantisation
    TEST_ASSERT_EQUAL_UINT8(2, b.routes[1].hops);
}

// An empty announce is still valid (count bytes + the caps field).
static void test_empty() {
    Announce a;  // 0 reports, 0 routes
    uint8_t buf[8];
    uint16_t n = announce_serialize(a, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_UINT16(HDR, n);

    Announce b;
    TEST_ASSERT_TRUE(announce_deserialize(buf, n, b));
    TEST_ASSERT_EQUAL_UINT8(0, b.n_reports);
    TEST_ASSERT_EQUAL_UINT8(0, b.n_routes);
    TEST_ASSERT_EQUAL_HEX16(0, b.caps);
}

// A truncated buffer must be rejected, not read out of bounds.
static void test_truncated_rejected() {
    Announce a = make_sample();
    uint8_t buf[256];
    uint16_t n = announce_serialize(a, buf, sizeof(buf));

    Announce b;
    TEST_ASSERT_FALSE(announce_deserialize(buf, n - 1, b));   // one byte short
    TEST_ASSERT_FALSE(announce_deserialize(buf, 1, b));       // shorter than header
    TEST_ASSERT_EQUAL_UINT8(0, b.n_reports);                  // out cleared on failure
}

// A header claiming more records than the buffer holds (or than our arrays can
// hold) must be rejected.
static void test_malformed_counts_rejected() {
    uint8_t buf[4] = {0xFF, 0xFF, 0x00, 0x00};  // claims 255 reports + 255 routes
    Announce b;
    TEST_ASSERT_FALSE(announce_deserialize(buf, sizeof(buf), b));
}

// A too-small output buffer drops what doesn't fit instead of overflowing: the
// header still serialises, routes get truncated, and the result round-trips.
static void test_output_truncation_is_graceful() {
    Announce a = make_sample();
    // Room for the header + both reports + exactly ONE route.
    uint16_t cap = HDR + 2 * ANNOUNCE_REPORT_BYTES + 1 * ANNOUNCE_ROUTE_BYTES;
    uint8_t buf[128];
    uint16_t n = announce_serialize(a, buf, cap);
    TEST_ASSERT_EQUAL_UINT16(cap, n);

    Announce b;
    TEST_ASSERT_TRUE(announce_deserialize(buf, n, b));
    TEST_ASSERT_EQUAL_UINT8(2, b.n_reports);
    TEST_ASSERT_EQUAL_UINT8(1, b.n_routes);   // second route dropped, cleanly

    // And a buffer too small for even the header yields 0.
    TEST_ASSERT_EQUAL_UINT16(0, announce_serialize(a, buf, 1));
}

// --- signed announce: sign -> verify round-trip, and the self-certifying id binding ---
static void test_signed_announce_roundtrip() {
    uint8_t sk[64], pk[32], seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 3 + 5);
    crypto_ed25519_key_pair(sk, pk, seed);

    Announce a = make_sample();
    uint8_t buf[256];
    uint16_t bl = announce_serialize(a, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_UINT16(announce_body_len(a), bl);

    uint8_t tail[ANNOUNCE_SIG_TAIL];
    announce_sign(buf, bl, pk, sk, tail);

    uint8_t got_pub[32];
    TEST_ASSERT_TRUE(announce_verify(buf, bl, tail, got_pub));     // sig checks out
    TEST_ASSERT_EQUAL_MEMORY(pk, got_pub, 32);                    // recovers the signer's key
    // The node id is the self-certifying hash of that key (the caller's binding check).
    TEST_ASSERT_TRUE(nid_from_pubkey(got_pub) == nid_from_pubkey(pk));
}

// A flipped body byte (or a wrong key) must fail verification.
static void test_signed_announce_tamper_rejected() {
    uint8_t sk[64], pk[32], seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);
    crypto_ed25519_key_pair(sk, pk, seed);

    Announce a = make_sample();
    uint8_t buf[256];
    uint16_t bl = announce_serialize(a, buf, sizeof(buf));
    uint8_t tail[ANNOUNCE_SIG_TAIL];
    announce_sign(buf, bl, pk, sk, tail);

    uint8_t got_pub[32];
    buf[5] ^= 0x01;                                                // tamper the signed body
    TEST_ASSERT_FALSE(announce_verify(buf, bl, tail, got_pub));
    buf[5] ^= 0x01;                                                // restore, then tamper the sig
    tail[40] ^= 0x01;
    TEST_ASSERT_FALSE(announce_verify(buf, bl, tail, got_pub));
}

// --- capability negotiation interop (Task 2) ---
// Build a LEGACY announce by hand: the pre-capability format is exactly the
// current format minus the 2-byte caps field, i.e. a 2-byte header with the
// HAS_CAPS bit CLEAR. This is what a node running the older firmware transmits.
static uint16_t make_legacy_announce(uint8_t* buf, uint16_t cap) {
    // One report + one route, no caps field.
    const uint16_t need = ANNOUNCE_HDR_BYTES
                        + ANNOUNCE_REPORT_BYTES + ANNOUNCE_ROUTE_BYTES;
    if (cap < need) return 0;
    uint16_t o = 0;
    buf[o++] = 1;   // n_reports = 1, HAS_CAPS clear
    buf[o++] = 1;   // n_routes  = 1
    // report: id[16], q, alias
    nid_write(buf + o, nid_from_u32(0xAAAAAAAAu)); o += 16;
    buf[o++] = 204; // q ~ 0.8
    buf[o++] = 9;   // alias
    // route: dst[16], next[16], cost_q[2], hops
    nid_write(buf + o, nid_from_u32(0xCCCCCCCCu)); o += 16;
    nid_write(buf + o, nid_from_u32(0xBBBBBBBBu)); o += 16;
    buf[o++] = 0x20; buf[o++] = 0x00;   // cost_q = 32 -> 2.0
    buf[o++] = 3;   // hops
    return o;
}

// A capability-aware node decodes a legacy (no-caps) announce fine, reading
// caps as 0 — so a new node still learns routing from an old neighbour.
static void test_new_decodes_legacy_as_caps0() {
    uint8_t buf[128];
    uint16_t n = make_legacy_announce(buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);

    Announce b;
    TEST_ASSERT_TRUE(announce_deserialize(buf, n, b));
    TEST_ASSERT_EQUAL_UINT8(1, b.n_reports);
    TEST_ASSERT_EQUAL_UINT8(1, b.n_routes);
    TEST_ASSERT_EQUAL_HEX16(0, b.caps);              // absent field defaults to none
    TEST_ASSERT_FALSE(b.has_caps);                   // and we noted the field was absent
    TEST_ASSERT_TRUE(b.reports[0].id == nid_from_u32(0xAAAAAAAAu));
    TEST_ASSERT_TRUE(b.routes[0].dst == nid_from_u32(0xCCCCCCCCu));

    // Re-serializing a legacy-decoded announce must reproduce the legacy bytes
    // exactly (no caps field re-inserted) — a faithful round-trip.
    uint8_t re[128];
    uint16_t rn = announce_serialize(b, re, sizeof(re));
    TEST_ASSERT_EQUAL_UINT16(n, rn);
    TEST_ASSERT_EQUAL_MEMORY(buf, re, n);
    TEST_ASSERT_EQUAL_UINT16(n, announce_body_len(b));   // body_len matches the legacy length
}

// A legacy decoder (no HAS_CAPS knowledge) rejects a caps announce cleanly
// instead of misparsing: its rep_byte carries bit7, which a legacy reader sees
// as n_reports > MAX_NEIGHBORS and rejects. We model the legacy reader's exact
// check against the byte our encoder produced.
static void test_legacy_rejects_caps_announce() {
    Announce a = make_sample();
    a.caps = CAP_SELECTIVE_ACK;
    uint8_t buf[256];
    uint16_t n = announce_serialize(a, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);

    // What a legacy decoder does: n_reports = buf[0] (no masking), reject if
    // it exceeds the fixed array. buf[0] has HAS_CAPS(0x80) set, so >= 128.
    uint8_t legacy_n_reports = buf[0];
    TEST_ASSERT_TRUE(legacy_n_reports > MAX_NEIGHBORS);   // legacy => reject, no misparse
    TEST_ASSERT_TRUE((buf[0] & ANNOUNCE_HAS_CAPS) != 0);
}

// Unknown capability bits must be preserved verbatim and never cause rejection
// (forward compatibility: a future bit set by a newer peer is ignored, not
// fatal).
static void test_unknown_caps_bits_ignored() {
    Announce a = make_sample();
    a.caps = 0xF008;   // bit3 + several reserved high bits, none defined today
    uint8_t buf[256];
    uint16_t n = announce_serialize(a, buf, sizeof(buf));

    Announce b;
    TEST_ASSERT_TRUE(announce_deserialize(buf, n, b));    // accepted, not rejected
    TEST_ASSERT_EQUAL_HEX16(0xF008, b.caps);              // preserved verbatim
    // A known-bit query on an unknown-bit-only field yields false, safely.
    TEST_ASSERT_FALSE((b.caps & CAP_SESSION_ADDR) != 0);
}

void setUp() {}
void tearDown() {}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_roundtrip);
    RUN_TEST(test_empty);
    RUN_TEST(test_truncated_rejected);
    RUN_TEST(test_malformed_counts_rejected);
    RUN_TEST(test_output_truncation_is_graceful);
    RUN_TEST(test_signed_announce_roundtrip);
    RUN_TEST(test_signed_announce_tamper_rejected);
    RUN_TEST(test_new_decodes_legacy_as_caps0);
    RUN_TEST(test_legacy_rejects_caps_announce);
    RUN_TEST(test_unknown_caps_bits_ignored);
    return UNITY_END();
}
