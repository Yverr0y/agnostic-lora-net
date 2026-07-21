#!/usr/bin/env python3
"""Demo: an aln_session secured message riding the Path-B tunnel wire.

Shows how the session layer plugs into the custom-app tunnel protocol
(docs/tcp-bridge.md) WITHOUT touching the node: the session frame is simply the
opaque `[payload]` inside the tunnel's `[addr_type][addr_len][addr][payload]`
envelope, itself HDLC-framed. The node still routes by the 16-byte node id in
the envelope; the 2-byte flow id and the crypto live entirely in the payload the
backbone never inspects.

This is the "savings in the app layer" option from the plan: the mesh header
keeps full node ids (zero firmware change), and the ~150 B of ad-hoc app
addressing/crypto a custom app would otherwise carry collapses to the 21 B of
session overhead here.

    python3 hostlib/examples/session_over_tunnel.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aln_session import Identity, Initiator, Responder, handshake_in_memory, OVERHEAD

# --- the tunnel wire (copied shape from scripts/tunnel_test.py) --------------
FLAG, ESC, MASK = 0x7E, 0x7D, 0x20
ADDR_LOCATOR = 0x01


def envelope(node_id: bytes, payload: bytes) -> bytes:
    return bytes([ADDR_LOCATOR, len(node_id)]) + node_id + payload


def unwrap(frame: bytes):
    atype, alen = frame[0], frame[1]
    assert atype == ADDR_LOCATOR
    return frame[2 : 2 + alen], frame[2 + alen :]


def hdlc(data: bytes) -> bytes:
    out = bytearray([FLAG])
    for b in data:
        if b in (FLAG, ESC):
            out += bytes([ESC, b ^ MASK])
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


def hdlc_decode(stream: bytes) -> bytes:
    out, esc, inframe = bytearray(), False, False
    for b in stream:
        if b == FLAG:
            if inframe and out:
                return bytes(out)
            inframe, esc, out = True, False, bytearray()
        elif not inframe:
            continue
        elif b == ESC:
            esc = True
        elif esc:
            out.append(b ^ MASK)
            esc = False
        else:
            out.append(b)
    return bytes(out)


def main() -> int:
    # Two contacts with pinned identities (IK: each knows the other's static).
    alice = Identity.generate()
    bob = Identity.generate()
    alice_node = os.urandom(16)   # 16-byte mesh node ids
    bob_node = os.urandom(16)

    i = Initiator(alice, remote_static=bob.static_pub(),
                  remote_verify_key=bob.signing.public_key())
    r = Responder(bob, remote_verify_key=alice.signing.public_key())
    sa, sb = handshake_in_memory(i, r)   # in real use, msgs 1-2(-3) ride the tunnel too
    print(f"handshake done; flow ids: alice<-{sa.local_flow:#06x} bob<-{sb.local_flow:#06x}")

    # Alice sends Bob a text message, secured, over the tunnel.
    text = b"meet at the ridge at 0600"
    session_frame = sa.encrypt(text)
    on_wire = hdlc(envelope(bob_node, session_frame))
    print(f"plaintext {len(text)} B -> session {len(session_frame)} B "
          f"(overhead {OVERHEAD} B) -> tunnel frame {len(on_wire)} B")

    # ... the mesh delivers `on_wire` to bob's node, which hands the payload up ...
    frame = hdlc_decode(on_wire)
    src_node, payload = unwrap(frame)
    kind, msg, ctr = sb.decrypt(payload)
    print(f"bob decrypted from {src_node.hex()[:8]}…: {msg!r} (counter {ctr})")
    assert msg == text

    # Bob returns a signed delivery receipt (rides the tunnel back the same way).
    receipt_on_wire = hdlc(envelope(alice_node, sb.make_receipt(ctr)))
    _, receipt_payload = unwrap(hdlc_decode(receipt_on_wire))
    _, rp, _ = sa.decrypt(receipt_payload)
    acked = sa.verify_receipt(rp)
    print(f"alice verified bob's delivery proof for counter {acked}  ✓")
    assert acked == ctr
    print("OK — secure round-trip + delivery proof over the unmodified tunnel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
