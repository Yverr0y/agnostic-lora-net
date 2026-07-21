"""Noise-protocol handshakes (XX and IK) over vetted primitives.

This is a compact, spec-faithful implementation of the two Noise patterns the
session layer needs, built ENTIRELY on `cryptography`'s primitives (X25519,
ChaCha20-Poly1305, HKDF-SHA256, SHA-256). We do not hand-roll any primitive —
only the Noise state machine that composes them, which is deterministic and
covered by initiator<->responder interop tests plus tamper tests.

Patterns (Noise notation):

    XX:  -> e
         <- e, ee, s, es
         -> s, se
      First contact: neither side knows the other's static key up front; both
      static keys are transmitted (encrypted) and mutually authenticated.

    IK:  <- s            (pre-message: initiator already knows responder static)
         -> e, es, s, ss
         <- e, ee, se
      Normal case: 1-RTT, responder static known out of band (signed announce
      / contact exchange), so fewer bytes on air.

Suite: Noise_*_25519_ChaChaPoly_SHA256. `split()` yields the two transport keys
(initiator->responder, responder->initiator); the session layer takes it from
there. `handshake_hash()` is the unique transcript id both sides agree on — the
session layer binds delivery receipts to it.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import Hash

# Noise_XX_25519_ChaChaPoly_SHA256 / Noise_IK_... — the protocol-name string is
# the initial chaining key material per the spec.
HASHLEN = 32
DHLEN = 32


def _sha256(data: bytes) -> bytes:
    h = Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def _hkdf(chaining_key: bytes, input_key_material: bytes, num_outputs: int):
    """Noise HKDF: returns `num_outputs` (2 or 3) 32-byte outputs.

    Implemented via HMAC-SHA256 exactly as the Noise spec defines HKDF (RFC 5869
    with the standard chaining), using the library's HKDFExpand for the expand
    step to avoid re-implementing HMAC.
    """
    # temp_key = HMAC(chaining_key, ikm); then expand with single-byte counters.
    import hmac

    temp_key = hmac.new(chaining_key, input_key_material, "sha256").digest()
    o1 = hmac.new(temp_key, b"\x01", "sha256").digest()
    o2 = hmac.new(temp_key, o1 + b"\x02", "sha256").digest()
    if num_outputs == 2:
        return o1, o2
    o3 = hmac.new(temp_key, o2 + b"\x03", "sha256").digest()
    return o1, o2, o3


class _CipherState:
    """Noise CipherState: an AEAD key plus a 64-bit nonce counter."""

    def __init__(self, key: bytes | None = None):
        self.key = key
        self.n = 0

    def has_key(self) -> bool:
        return self.key is not None

    def _nonce(self) -> bytes:
        # Noise: 32 bits of zeros ‖ 64-bit little-endian counter = 12-byte nonce.
        return b"\x00\x00\x00\x00" + struct.pack("<Q", self.n)

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.key is None:
            return plaintext
        ct = ChaCha20Poly1305(self.key).encrypt(self._nonce(), plaintext, ad)
        self.n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.key is None:
            return ciphertext
        pt = ChaCha20Poly1305(self.key).decrypt(self._nonce(), ciphertext, ad)
        self.n += 1
        return pt


class _SymmetricState:
    """Noise SymmetricState: chaining key + running transcript hash."""

    def __init__(self, protocol_name: bytes):
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name + b"\x00" * (HASHLEN - len(protocol_name))
        else:
            self.h = _sha256(protocol_name)
        self.ck = self.h
        self.cipher = _CipherState()

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, temp_k = _hkdf(self.ck, input_key_material, 2)
        self.cipher = _CipherState(temp_k)

    def mix_hash(self, data: bytes) -> None:
        self.h = _sha256(self.h + data)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ct = self.cipher.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        pt = self.cipher.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self):
        temp_k1, temp_k2 = _hkdf(self.ck, b"", 2)
        return _CipherState(temp_k1), _CipherState(temp_k2)


def _dh(private: X25519PrivateKey, public: X25519PublicKey) -> bytes:
    return private.exchange(public)


def _pub_bytes(pub: X25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class HandshakeError(Exception):
    pass


class NoiseHandshake:
    """A Noise XX or IK handshake, driven message-by-message.

    Usage: construct with pattern, role, and keys; then alternate
    `write_message(payload)` / `read_message(data)` in the pattern's order until
    `finished` is True, at which point `transport_keys()` returns the send/recv
    CipherStates and `handshake_hash()` the transcript id.
    """

    # token sequences per pattern (post pre-message)
    _PATTERNS = {
        "XX": [["e"], ["e", "ee", "s", "es"], ["s", "se"]],
        "IK": [["e", "es", "s", "ss"], ["e", "ee", "se"]],
    }

    def __init__(
        self,
        pattern: str,
        initiator: bool,
        static: X25519PrivateKey,
        remote_static_pub: bytes | None = None,
        prologue: bytes = b"",
    ):
        if pattern not in self._PATTERNS:
            raise ValueError(f"unsupported pattern {pattern}")
        self.pattern = pattern
        self.initiator = initiator
        self.s = static
        self.e: X25519PrivateKey | None = None
        self.rs: X25519PublicKey | None = (
            X25519PublicKey.from_public_bytes(remote_static_pub)
            if remote_static_pub
            else None
        )
        self.re: X25519PublicKey | None = None

        name = f"Noise_{pattern}_25519_ChaChaPoly_SHA256".encode()
        self.sym = _SymmetricState(name)
        self.sym.mix_hash(prologue)

        # IK pre-message: responder's static is known to both before msg 1.
        if pattern == "IK":
            if initiator:
                if self.rs is None:
                    raise ValueError("IK initiator needs remote_static_pub")
                self.sym.mix_hash(_pub_bytes(self.rs))
            else:
                self.sym.mix_hash(_pub_bytes(self.s.public_key()))

        self._messages = list(self._PATTERNS[pattern])
        self._msg_index = 0
        self.finished = False
        self._split = None

    # --- driving the handshake -------------------------------------------
    def _next_tokens(self):
        tokens = self._messages[self._msg_index]
        self._msg_index += 1
        return tokens

    def write_message(self, payload: bytes = b"") -> bytes:
        tokens = self._next_tokens()
        buf = bytearray()
        for t in tokens:
            if t == "e":
                self.e = X25519PrivateKey.generate()
                epub = _pub_bytes(self.e.public_key())
                buf += epub
                self.sym.mix_hash(epub)
            elif t == "s":
                spub = _pub_bytes(self.s.public_key())
                buf += self.sym.encrypt_and_hash(spub)
            elif t == "ee":
                self.sym.mix_key(_dh(self.e, self.re))
            elif t == "es":
                self.sym.mix_key(
                    _dh(self.e, self.rs) if self.initiator else _dh(self.s, self.re)
                )
            elif t == "se":
                self.sym.mix_key(
                    _dh(self.s, self.re) if self.initiator else _dh(self.e, self.rs)
                )
            elif t == "ss":
                self.sym.mix_key(_dh(self.s, self.rs))
        buf += self.sym.encrypt_and_hash(payload)
        self._maybe_finish()
        return bytes(buf)

    def read_message(self, data: bytes) -> bytes:
        tokens = self._next_tokens()
        mv = memoryview(data)
        off = 0
        try:
            for t in tokens:
                if t == "e":
                    self.re = X25519PublicKey.from_public_bytes(bytes(mv[off : off + DHLEN]))
                    self.sym.mix_hash(bytes(mv[off : off + DHLEN]))
                    off += DHLEN
                elif t == "s":
                    n = DHLEN + (16 if self.sym.cipher.has_key() else 0)
                    spub = self.sym.decrypt_and_hash(bytes(mv[off : off + n]))
                    self.rs = X25519PublicKey.from_public_bytes(spub)
                    off += n
                elif t == "ee":
                    self.sym.mix_key(_dh(self.e, self.re))
                elif t == "es":
                    self.sym.mix_key(
                        _dh(self.e, self.rs) if self.initiator else _dh(self.s, self.re)
                    )
                elif t == "se":
                    self.sym.mix_key(
                        _dh(self.s, self.re) if self.initiator else _dh(self.e, self.rs)
                    )
                elif t == "ss":
                    self.sym.mix_key(_dh(self.s, self.rs))
            payload = self.sym.decrypt_and_hash(bytes(mv[off:]))
        except Exception as exc:  # AEAD tag failure, bad point, short buffer
            raise HandshakeError(str(exc)) from exc
        self._maybe_finish()
        return payload

    def _maybe_finish(self):
        if self._msg_index >= len(self._messages):
            self.finished = True
            self._split = self.sym.split()

    # --- results ----------------------------------------------------------
    def transport_keys(self):
        """(send_cipher, recv_cipher) oriented for THIS party."""
        if not self.finished:
            raise HandshakeError("handshake not complete")
        c1, c2 = self._split  # c1 = initiator->responder, c2 = responder->initiator
        return (c1, c2) if self.initiator else (c2, c1)

    def transport_keys_raw(self):
        """(k_i2r, k_r2i) 32-byte keys, orientation-independent."""
        if not self.finished:
            raise HandshakeError("handshake not complete")
        return self._split[0].key, self._split[1].key

    def handshake_hash(self) -> bytes:
        if not self.finished:
            raise HandshakeError("handshake not complete")
        return self.sym.h

    def remote_static(self) -> bytes | None:
        return _pub_bytes(self.rs) if self.rs else None
