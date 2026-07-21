"""aln_session — a small, vetted secure-session layer for ALN custom apps.

For apps that speak the raw tunnel protocol (docs/tcp-bridge.md Path B) and have
no end-to-end crypto of their own. Reticulum/LXMF apps should use Reticulum's
own crypto instead — see docs/INTEGRATING-AGNOSTIC-LORA-NET.md.

Runs entirely in host bridge code: ZERO node firmware and ZERO mobile-app
changes. Built on `cryptography` primitives (X25519, ChaCha20-Poly1305,
HKDF-SHA256, Ed25519) — no hand-rolled crypto.

Typical use::

    from aln_session import Identity, Initiator, Responder, handshake_in_memory

    alice = Identity.generate()
    bob = Identity.generate()

    # IK (bob's static known out of band); XX if remote_static is omitted.
    i = Initiator(alice, remote_static=bob.static_pub(),
                  remote_verify_key=bob.signing.public_key())
    r = Responder(bob, remote_verify_key=alice.signing.public_key())
    sa, sb = handshake_in_memory(i, r)

    frame = sa.encrypt(b"hello over LoRa")     # -> tunnel payload (21 B overhead)
    kind, msg, ctr = sb.decrypt(frame)         # -> (MSG_DATA, b"hello over LoRa", 0)
    receipt = sb.make_receipt(ctr)             # signed delivery proof
    _, rp, _ = sa.decrypt(receipt)
    assert sa.verify_receipt(rp) == ctr
"""

from .identity import Identity, load_static_pub, load_verify_key
from .noise import HandshakeError, NoiseHandshake
from .connect import Initiator, Responder, handshake_in_memory
from .session import (
    MSG_DATA,
    MSG_RECEIPT,
    MSG_REKEY,
    OVERHEAD,
    ReplayError,
    Session,
    SessionError,
)

__all__ = [
    "Identity",
    "load_static_pub",
    "load_verify_key",
    "NoiseHandshake",
    "HandshakeError",
    "Initiator",
    "Responder",
    "handshake_in_memory",
    "Session",
    "SessionError",
    "ReplayError",
    "MSG_DATA",
    "MSG_RECEIPT",
    "MSG_REKEY",
    "OVERHEAD",
]
