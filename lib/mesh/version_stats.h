// version_stats.h — counts frames dropped because their protocol major version
// isn't the one this node speaks (Task 2 RX rule).
//
// The network-header version (packet.h PROTO_VERSION) is the major version. A
// frame carrying any other major version is dropped — but silently dropping it
// hides a mixed-version mesh, exactly the situation the version byte exists to
// make visible. This tiny counter records how many such frames were dropped and
// the most recent foreign version seen, so the node can surface it on its info
// line and the controller map can flag "there's an incompatible node nearby".
//
// Header-only and pure (no I/O), so it's exercised in host tests.
#pragma once

#include <stdint.h>

namespace mesh {

class VersionStats {
public:
    // Call for every frame whose major version != our own. `ver` is the version
    // read off the wire. Returns the running drop count (for convenience).
    uint32_t on_foreign(uint8_t ver) {
        drops_++;
        last_ver_ = ver;
        return drops_;
    }

    uint32_t drops()    const { return drops_; }
    // The most recently seen foreign version, or 0xFF if none seen yet.
    uint8_t  last_ver() const { return last_ver_; }
    bool     any()      const { return drops_ > 0; }

    void reset() { drops_ = 0; last_ver_ = 0xFF; }

private:
    uint32_t drops_    = 0;
    uint8_t  last_ver_ = 0xFF;
};

} // namespace mesh
