// capabilities.h — per-node capability bits, negotiated via signed announces.
//
// The wire format is unfrozen, and until now any change meant a flag-day
// reflash of the whole mesh. Capability bits end that: a node advertises what
// it supports in its announce, peers store it (neighbor_table), and any future
// feature gates on `neighbor_supports(id, CAP_X)` so a mixed-version mesh keeps
// working. The rule is additive — UNKNOWN BITS MUST BE IGNORED, never rejected
// — so a v-old node happily ignores bits a v-new node sets, and vice versa.
//
// This is the mechanism that makes "the last flag-day change" actually the
// last: from here on, wire additions ride a capability bit instead of a
// version bump. See docs/wire-format.md.
#pragma once

#include <stdint.h>

namespace mesh {

// Capability bitfield carried in the announce (u16, little-endian). Bit
// assignments are a permanent registry — never renumber a shipped bit.
enum Capability : uint16_t {
    CAP_SELECTIVE_ACK  = 1u << 0,  // SAR selective-ACK bitmaps (Stretch A)
    CAP_SESSION_ADDR   = 1u << 1,  // 2-byte session/flow short addresses (Task 3 host layer)
    CAP_DICT_COMPRESS1 = 1u << 2,  // dictionary text compression v1 (future)
    // bits 3..15 reserved — advertise 0, ignore on receive.
};

// What THIS firmware implements today. The advanced features above live in the
// host bridge layer (session addressing) or are not yet built (selective-ACK is
// Stretch A, dictionary compression is future), so a stock node implements none
// of them yet — but it still advertises the field, which tells peers it speaks
// the capability-negotiated format at all. Flip a bit here the moment the
// matching feature lands in firmware.
constexpr uint16_t NODE_CAPS = 0;

} // namespace mesh
