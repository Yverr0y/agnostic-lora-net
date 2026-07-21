"""Identity + static keys for the ALN session layer.

An endpoint has two keypairs:
  * an X25519 static keypair — its long-term Noise identity (proves who it is
    during the handshake), and
  * an Ed25519 signing keypair — for delivery receipts.

For a Reticulum contact these come from that contact's existing identity out of
band; for a bring-up bench they're generated and pinned. This module keeps the
serialization boilerplate in one place so the bridge and tests agree on formats.
Raw 32-byte encodings match what the firmware / node ids already use.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

_RAW = serialization.Encoding.Raw
_PUB = serialization.PublicFormat.Raw
_PRIV = serialization.PrivateFormat.Raw
_NOENC = serialization.NoEncryption()


def x25519_pub_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(_RAW, _PUB)


def ed25519_pub_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(_RAW, _PUB)


@dataclass
class Identity:
    """An endpoint's long-term keys."""

    static: X25519PrivateKey        # Noise static (identity) key
    signing: Ed25519PrivateKey      # receipt signing key

    @classmethod
    def generate(cls) -> "Identity":
        return cls(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())

    @classmethod
    def from_seeds(cls, static_seed: bytes, signing_seed: bytes) -> "Identity":
        """Deterministic identity from two 32-byte seeds (tests / reproducible benches)."""
        if len(static_seed) != 32 or len(signing_seed) != 32:
            raise ValueError("seeds must be 32 bytes")
        return cls(
            X25519PrivateKey.from_private_bytes(static_seed),
            Ed25519PrivateKey.from_private_bytes(signing_seed),
        )

    # --- public halves (what a peer needs to know about us) ---------------
    def static_pub(self) -> bytes:
        return x25519_pub_bytes(self.static.public_key())

    def signing_pub(self) -> bytes:
        return ed25519_pub_bytes(self.signing.public_key())

    # --- serialization ----------------------------------------------------
    def static_priv_bytes(self) -> bytes:
        return self.static.private_bytes(_RAW, _PRIV, _NOENC)

    def signing_priv_bytes(self) -> bytes:
        return self.signing.private_bytes(_RAW, _PRIV, _NOENC)


def load_verify_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def load_static_pub(raw: bytes) -> bytes:
    """Validate a raw X25519 public key and return it unchanged (contract check)."""
    X25519PublicKey.from_public_bytes(raw)  # raises on wrong length
    return raw
