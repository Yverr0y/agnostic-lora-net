# Wire format & compatibility policy

This is the on-air contract for agnostic-LoRa-Net. It documents where the
protocol version lives, the capability-bit registry, and the rules that let the
format evolve without a flag-day reflash of the whole mesh.

Golden byte vectors for every packet type are checked in at
`test/test_vectors/` and verified both directions (decode→fields and
fields→bytes) by `pio test -e native`. Those vectors ARE this contract in
executable form; the same canonical bytes seed the fuzzers (`fuzz/corpus/`).

## Layered headers

```
[ LinkHeader (4 B) ][ NetHeader (37 B) ][ payload … ]
 |<--- per hop --->| |<---------- end to end ---------->|
```

All multi-byte fields are little-endian. Structs are packed (`sizeof == on-air`).

### NetHeader (`include/packet.h`)

| field | bytes | notes |
|---|---|---|
| `ver_type` | 1 | high nibble = **protocol major version**, low nibble = `PacketType` |
| `flags` | 1 | `NetFlags` |
| `ttl` | 1 | decremented per relay |
| `dst` | 16 | destination node id (`0xFF…` = broadcast) |
| `src` | 16 | originating node id |
| `pkt_id` | 2 | dedup + end-to-end ACK correlation |

## Protocol version (the major version)

The high nibble of `ver_type` is the protocol **major** version — currently
**2** (`PROTO_VERSION`). It changes only on a genuinely incompatible reframing
of the network header itself. Because it is 4 bits, versions 0–15 are possible.

**RX rule (`major = drop`):** a node drops any frame whose major version isn't
the one it speaks. It does **not** guess or partially parse. Drops are counted
(`lib/mesh/version_stats.h`) and surfaced on the node's console as

```
[ver] drops=<n> last=<seen-version> supported=<our-version>
```

which the controller ingests (`KindVersionDrop`) so a mixed-version mesh is
visible on the map instead of silently failing. The line is emitted only once a
foreign-version frame has actually been heard, so a healthy mesh stays quiet.

## Capabilities (the forward-compatibility lever)

Bumping the major version is the blunt instrument. The fine instrument is the
**capability bitfield**: a node advertises what it supports, peers remember it
(`neighbor_table`), and any new feature engages only with peers that advertise
the matching bit (`Router::neighbor_supports(id, CAP_X)`). This is what makes
"the last flag-day change" actually the last — from here on, additive wire
features ride a capability bit, not a version bump.

### Where capabilities live

Capabilities are carried in the **signed announce** (so they're authenticated by
the same Ed25519 signature that proves node identity). The announce header:

```
u8  rep_byte    bit7 = HAS_CAPS, bits0..6 = n_reports (0..MAX_NEIGHBORS)
u8  n_routes
u16 caps        present IFF HAS_CAPS   (little-endian, capability bits)
… reports, routes …
```

The `HAS_CAPS` bit makes the field self-describing, which is what avoids a
flag-day for its *introduction*:

- A capability-aware node **always** sets `HAS_CAPS` (advertising its caps, even
  when 0 — that itself signals "I speak the negotiated format").
- A capability-aware node decoding a **legacy** announce (no `HAS_CAPS`) reads it
  fine as `caps = 0`, so it still learns routing from an old neighbour.
- A **legacy** decoder reading a new announce sees `rep_byte >= 0x80`, i.e.
  `n_reports` far above `MAX_NEIGHBORS`, and cleanly **rejects** it rather than
  misparsing. No network-header version bump is needed.

### Capability bit registry (`lib/mesh/capabilities.h`)

This is a permanent registry — never renumber a shipped bit.

| bit | name | meaning |
|---|---|---|
| 0 | `CAP_SELECTIVE_ACK` | SAR selective-ACK bitmaps (Stretch A) |
| 1 | `CAP_SESSION_ADDR` | 2-byte session/flow short addresses (host session layer) |
| 2 | `CAP_DICT_COMPRESS1` | dictionary text compression v1 (future) |
| 3–15 | reserved | advertise 0; **ignore on receive** |

**Unknown bits MUST be ignored, never rejected.** A newer peer setting a
reserved bit must not cause an older peer to drop the announce — the decoder
preserves the raw `caps` value verbatim and callers test only the bits they know.

`NODE_CAPS` is the set this firmware actually implements today (currently 0 — the
advanced features live in the host bridge layer or aren't built yet). Flip a bit
there the moment its feature lands in firmware.

## Compatibility policy (summary)

- **Minor / additive change** → gate it behind a new capability bit. Peers that
  don't advertise the bit never receive the new form. No version bump.
- **Major / incompatible change** → bump `PROTO_VERSION`. Old and new nodes drop
  each other's frames cleanly and the drop counter makes it visible.
- The announce capability field's introduction (this batch) is the **last**
  change that required reflashing the whole mesh to interoperate; it was made
  backward-tolerant via `HAS_CAPS` so even it degrades gracefully.

## Regenerating the golden vectors

If the format changes intentionally, regenerate the byte arrays in
`test/test_vectors/test_main.cpp` from the library builders (a small host
program that calls `announce_serialize`, `ctrl_build`, `telem_build_*`,
`loc_build_*`, `sar_build_fragment` with the fixed sample inputs and the
deterministic keypair `seed[i] = i*7+1`), and update this document in the same
commit. Reviewers then see the wire change as a diff of real bytes.
