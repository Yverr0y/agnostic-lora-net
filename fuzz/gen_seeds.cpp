// Seed-corpus generator: writes canonical, valid wire messages into
// fuzz/corpus/<target>/ using the library's own builders, so every fuzzer
// starts from well-formed inputs instead of discovering the format from
// scratch. Built and run by `make seeds` (host tool, no sanitizers needed).
//
// The same builders produce the golden vectors in test/vectors/ (handoff plan
// Task 2) — these seeds ARE the compatibility corpus, in fuzzer clothing.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "packet.h"
#include "announce_codec.h"
#include "control.h"
#include "locator_dir.h"
#include "sar.h"
#include "telemetry.h"
#include "kiss.h"
#include "node_table.h"   // nid_from_pubkey
#include "monocypher-ed25519.h"

using namespace mesh;

static std::string g_dir;

static void dump(const char* target, const char* name, const uint8_t* d, size_t n) {
    std::string path = g_dir + "/" + target + "/" + name + ".bin";
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { fprintf(stderr, "cannot write %s (mkdir first?)\n", path.c_str()); exit(1); }
    fwrite(d, 1, n, f);
    fclose(f);
    printf("  %-40s %3zu B\n", path.c_str(), n);
}

// Deterministic keypair (same seed rule as test/test_control: seed[i] = i*7+1).
static void test_keypair(uint8_t sk[64], uint8_t pk[32]) {
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);
    crypto_ed25519_key_pair(sk, pk, seed);
}

static Announce sample_announce() {
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

int main(int argc, char** argv) {
    g_dir = argc > 1 ? argv[1] : "corpus";
    uint8_t sk[64], pk[32];
    test_keypair(sk, pk);
    uint8_t buf[1024];

    // --- announce: plain body + signed body||tail ---
    Announce a = sample_announce();
    uint16_t n = announce_serialize(a, buf, sizeof(buf));
    dump("announce", "announce_body", buf, n);
    announce_sign(buf, n, pk, sk, buf + n);
    dump("announce", "announce_signed", buf, (size_t)n + ANNOUNCE_SIG_TAIL);

    // --- control: pubkey || message (matches fuzz_control's input layout) ---
    node_id_t target = nid_from_u32(0x22222222u);
    node_id_t victim = nid_from_u32(0x33333333u);
    uint8_t msg[512];
    memcpy(msg, pk, 32);
    n = ctrl_build(CTRL_POWER, target, 14, 7, sk, msg + 32, sizeof(msg) - 32);
    dump("control", "power", msg, 32u + n);
    n = ctrl_build_block(CTRL_BLOCK, target, victim, 30, 8, sk, msg + 32, sizeof(msg) - 32);
    dump("control", "block", msg, 32u + n);
    uint8_t cfg[CTRL_RETUNE_CFG] = {0x40, 0x42, 0x0F, 0x35, 0x90, 0xD0, 0x03, 0x00,
                                    11, 5, 0x12, 0x08, 0x00};
    n = ctrl_build_retune(target, cfg, 9, sk, msg + 32, sizeof(msg) - 32);
    dump("control", "retune", msg, 32u + n);
    n = ctrl_build_ack(CTRL_POWER, target, 14, 1, 7, msg + 32, sizeof(msg) - 32);
    dump("control", "ack", msg, 32u + n);

    // --- telemetry ---
    n = telem_build_batt(3712, 88, buf, sizeof(buf));
    dump("telemetry", "batt", buf, n);
    n = telem_build_query(target, buf, sizeof(buf));
    dump("telemetry", "query", buf, n);
    TelemNbr nbrs[2] = {{nid_from_u32(0xAAAAAAAAu), 90, 85, 7, -88},
                        {nid_from_u32(0xBBBBBBBBu), 40, 55, -3, -110}};
    n = telem_build_reply(3650, 76, 1234, 14, 11, TELEM_FLAG_MOBILE,
                          "0.15.0", "bench-node", nbrs, 2, buf, sizeof(buf));
    dump("telemetry", "reply", buf, n);

    // --- locator directory ---
    const uint8_t rid[10] = {0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6};
    n = loc_build_register(0x0102, 7, 600, rid, sizeof(rid), buf, sizeof(buf));
    dump("loc", "register", buf, n);
    n = loc_build_query(0x1234, rid, sizeof(rid), buf, sizeof(buf));
    dump("loc", "query", buf, n);
    n = loc_build_reply(0x1234, 0x0102, 7, 600, target, rid, sizeof(rid), buf, sizeof(buf));
    dump("loc", "reply", buf, n);

    // --- SAR: an op-sequence feeding a full valid 2-fragment transfer,
    //     then a query op, then NACK + DONE parses (fuzz_sar's format:
    //     [op][len][payload...]) ---
    {
        uint8_t blob[200];
        for (size_t i = 0; i < sizeof(blob); i++) blob[i] = (uint8_t)(i * 3);
        uint32_t crc = sar_crc32(blob, sizeof(blob));
        uint8_t seq[1024];
        size_t off = 0;
        for (uint16_t idx = 0; idx < sar_frag_count(sizeof(blob)); idx++) {
            uint8_t frag[SAR_HDR_BYTES + SAR_CHUNK];
            uint16_t fn = sar_build_fragment(blob, sizeof(blob), 0x0101, crc, idx,
                                             frag, sizeof(frag));
            seq[off++] = 0;                 // op: add
            seq[off++] = (uint8_t)fn;       // len
            memcpy(seq + off, frag, fn);
            off += fn;
        }
        seq[off++] = 6; seq[off++] = 0;     // op: query missing/complete/verify
        uint16_t miss[2] = {1, 3};
        uint8_t nk[64];
        uint16_t nn = sar_build_nack(0x0101, miss, 2, nk, sizeof(nk));
        seq[off++] = 4; seq[off++] = (uint8_t)nn;
        memcpy(seq + off, nk, nn); off += nn;
        nn = sar_build_done(0x0101, nk, sizeof(nk));
        seq[off++] = 5; seq[off++] = (uint8_t)nn;
        memcpy(seq + off, nk, nn); off += nn;
        dump("sar", "transfer_ops", seq, off);
    }

    // --- ARQ: a track / ack / tick op sequence (fuzz_arq's [op][a][b] format) ---
    {
        const uint8_t ops[] = {0, 5, 32,    // track seq=5, 32-byte frame
                               3, 0, 0,     // next_seq
                               2, 0xE8, 3,  // tick +1000 ms
                               1, 5, 0,     // ack seq 5
                               0, 9, 200,   // track seq=9
                               2, 0xFF, 0xFF};
        dump("arq", "ops", ops, sizeof(ops));
    }

    // --- KISS: an encoded frame whose payload needs both escapes ---
    {
        const uint8_t payload[] = {'h', 'i', KISS_FEND, KISS_FESC, 0x00, 0x7F};
        n = kiss_encode(KISS_CMD_DATA, payload, sizeof(payload), buf, sizeof(buf));
        dump("kiss", "frame", buf, n);
    }

    // --- frame: full on-air frames (LinkHeader+NetHeader+payload) ---
    {
        uint8_t frame[512];
        LinkHeader lh{LINK_ADDR_NONE, LINK_ADDR_BROADCAST, 1, 0};
        node_id_t src = nid_from_pubkey(pk);

        auto emit = [&](PacketType t, const uint8_t* pay, uint16_t pn, const char* name) {
            NetHeader nh{};
            nh.ver_type = net_ver_type(t);
            nh.flags = 0;
            nh.ttl = DEFAULT_TTL;
            nh.dst = NODE_ID_BROADCAST;
            nh.src = src;
            nh.pkt_id = 0x0101;
            memcpy(frame, &lh, sizeof(lh));
            memcpy(frame + sizeof(lh), &nh, sizeof(nh));
            memcpy(frame + HEADER_BYTES, pay, pn);
            dump("frame", name, frame, (size_t)HEADER_BYTES + pn);
        };

        // Beacon: BeaconPayload + announce body + signature tail.
        uint8_t bpay[512];
        BeaconPayload bp{0, 89, 4242};
        memcpy(bpay, &bp, sizeof(bp));
        uint16_t bn = announce_serialize(a, bpay + sizeof(bp), sizeof(bpay) - sizeof(bp));
        announce_sign(bpay + sizeof(bp), bn, pk, sk, bpay + sizeof(bp) + bn);
        emit(PKT_BEACON, bpay, (uint16_t)(sizeof(bp) + bn + ANNOUNCE_SIG_TAIL), "beacon_signed");

        uint8_t cmsg[256];
        uint16_t cn = ctrl_build(CTRL_POWER, src, 14, 7, sk, cmsg, sizeof(cmsg));
        emit(PKT_CONTROL, cmsg, cn, "control_power");

        cn = telem_build_batt(3712, 88, cmsg, sizeof(cmsg));
        emit(PKT_TELEM, cmsg, cn, "telem_batt");

        cn = loc_build_query(0x1234, rid, sizeof(rid), cmsg, sizeof(cmsg));
        emit(PKT_LOC, cmsg, cn, "loc_query");

        uint8_t blob[64];
        memset(blob, 0x5A, sizeof(blob));
        cn = sar_build_fragment(blob, sizeof(blob), 0x0101,
                                sar_crc32(blob, sizeof(blob)), 0, cmsg, sizeof(cmsg));
        emit(PKT_DATA, cmsg, cn, "data_sar_frag");
    }

    printf("seed corpus written under %s/\n", g_dir.c_str());
    return 0;
}
