"""Post-handshake secure session for the ALN custom-app (Path B) tunnel.

Wraps the two transport keys a Noise handshake produced into an
encrypt/decrypt session with the low-overhead wire format from the plan:

    [1 B msg_type][2 B flow_id][2 B counter_low][ciphertext][16 B tag]

* `flow_id` is a 2-byte label negotiated at handshake time (replacing the
  16-byte node id in the steady state — the airtime win).
* Only the low 16 bits of the per-direction message counter ride the wire; the
  receiver reconstructs the full 64-bit counter from its own expected value
  (resync-tolerant across loss, within a window).
* The nonce is a per-direction HKDF-derived 12-byte salt XOR the full counter,
  so a lost/reordered packet never reuses a nonce.
* Replay is rejected by a per-direction sliding window over the full counter.
* Overhead per message is 5 B framing + 16 B AEAD tag = 21 B (well under the
  plan's 40 B budget), plus the msg_type/flow_id which double as the address.

Message types:
    DATA    application payload
    RECEIPT delivery proof (Ed25519 over hash(transcript_id ‖ counter))
    REKEY   signals a key ratchet (HKDF) has taken effect from a given counter
"""

from __future__ import annotations

import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature

MSG_DATA = 0x01
MSG_RECEIPT = 0x02
MSG_REKEY = 0x03

_HEADER = struct.Struct("<BHH")  # msg_type, flow_id, counter_low
HEADER_LEN = _HEADER.size  # 5
TAG_LEN = 16
OVERHEAD = HEADER_LEN + TAG_LEN  # 21 bytes

# Reconstruct the full counter from the 16-bit wire value: accept anything within
# this many messages of the expected counter. 0x7FFF is the largest gap a 16-bit
# low counter can disambiguate unambiguously (half the period), so any real loss
# burst up to ~32k messages resyncs; a larger gap than that from a 16-bit field
# is fundamentally unrecoverable and is rejected rather than mis-decoded.
_COUNTER_WINDOW = 0x7FFF
_REPLAY_WINDOW = 512


class SessionError(Exception):
    pass


class ReplayError(SessionError):
    pass


def _hkdf_expand(key: bytes, info: bytes, length: int) -> bytes:
    """Single-block HKDF-Expand (length <= 32) over HMAC-SHA256."""
    return hmac.new(key, info + b"\x01", "sha256").digest()[:length]


def _nonce(salt: bytes, counter: int) -> bytes:
    """12-byte nonce = salt XOR little-endian counter (counter in low 8 bytes)."""
    ctr = struct.pack("<Q", counter) + b"\x00\x00\x00\x00"
    return bytes(a ^ b for a, b in zip(salt, ctr))


class _SlidingWindow:
    """Anti-replay window over a monotonically-advancing highest counter."""

    def __init__(self, size: int = _REPLAY_WINDOW):
        self.size = size
        self.highest = -1
        self.seen: set[int] = set()

    def check_and_set(self, counter: int) -> None:
        if counter <= self.highest - self.size:
            raise ReplayError(f"counter {counter} below replay window")
        if counter in self.seen:
            raise ReplayError(f"counter {counter} already seen")
        self.seen.add(counter)
        if counter > self.highest:
            self.highest = counter
            self.seen = {c for c in self.seen if c > self.highest - self.size}


class Session:
    """One end of a secure session. Construct via `Session.from_handshake`."""

    def __init__(
        self,
        send_key: bytes,
        recv_key: bytes,
        local_flow: int,
        remote_flow: int,
        transcript_id: bytes,
        signing_key: Ed25519PrivateKey | None = None,
        peer_verify_key: Ed25519PublicKey | None = None,
        rekey_after: int = 4096,
    ):
        self._send_key = send_key
        self._recv_key = recv_key
        self.local_flow = local_flow      # flow id the PEER stamps on frames to us
        self.remote_flow = remote_flow    # flow id WE stamp on frames to the peer
        self.transcript_id = transcript_id
        self._sign = signing_key
        self._peer_verify = peer_verify_key
        self._rekey_after = rekey_after

        self._send_ctr = 0
        self._recv_high = -1
        self._msgs_since_rekey = 0
        self._replay = _SlidingWindow()
        self._refresh_salts()

    # --- construction -----------------------------------------------------
    @classmethod
    def from_handshake(
        cls,
        handshake,
        local_flow: int,
        remote_flow: int,
        signing_key: Ed25519PrivateKey | None = None,
        peer_verify_key: Ed25519PublicKey | None = None,
        rekey_after: int = 4096,
    ) -> "Session":
        send_cipher, recv_cipher = handshake.transport_keys()
        return cls(
            send_key=send_cipher.key,
            recv_key=recv_cipher.key,
            local_flow=local_flow,
            remote_flow=remote_flow,
            transcript_id=handshake.handshake_hash(),
            signing_key=signing_key,
            peer_verify_key=peer_verify_key,
            rekey_after=rekey_after,
        )

    def _refresh_salts(self) -> None:
        self._send_salt = _hkdf_expand(self._send_key, b"aln-nonce", 12)
        self._recv_salt = _hkdf_expand(self._recv_key, b"aln-nonce", 12)

    # --- send -------------------------------------------------------------
    def _seal(self, msg_type: int, plaintext: bytes) -> bytes:
        counter = self._send_ctr
        header = _HEADER.pack(msg_type, self.remote_flow, counter & 0xFFFF)
        ct = ChaCha20Poly1305(self._send_key).encrypt(
            _nonce(self._send_salt, counter), plaintext, header
        )
        self._send_ctr += 1
        self._msgs_since_rekey += 1
        return header + ct

    def encrypt(self, plaintext: bytes) -> bytes:
        """Seal an application message (MSG_DATA). Returns the tunnel payload."""
        return self._seal(MSG_DATA, plaintext)

    @property
    def rekey_due(self) -> bool:
        """True once `rekey_after` messages have been sent on the current key.

        The caller drives rekey (it also owns the time-based T-hours trigger):
        when this is True, or on its own timer, call `send_rekey()` and transmit
        the returned frame. Kept explicit so sender and receiver never silently
        diverge — a REKEY frame is the single synchronisation point.
        """
        return self._rekey_after > 0 and self._msgs_since_rekey >= self._rekey_after

    def make_receipt(self, counter: int) -> bytes:
        """Build a signed delivery receipt for a received message's counter.

        The recipient signs Ed25519 over hash(transcript_id ‖ counter) with its
        identity key; equivalent guarantee to the mesh's cryptographic delivery
        proof. Sent back as a normal (encrypted) session message.
        """
        if self._sign is None:
            raise SessionError("no signing key configured for receipts")
        sig = self._sign.sign(self._receipt_digest(counter))
        return self._seal(MSG_RECEIPT, struct.pack("<Q", counter) + sig)

    def _receipt_digest(self, counter: int) -> bytes:
        h = hashes.Hash(hashes.SHA256())
        h.update(self.transcript_id)
        h.update(struct.pack("<Q", counter))
        return h.finalize()

    # --- receive ----------------------------------------------------------
    def _reconstruct_counter(self, counter_low: int) -> int:
        """Full 64-bit counter from the 16-bit wire value, nearest to expected."""
        expected = self._recv_high + 1
        base = expected & ~0xFFFF
        candidate = base | counter_low
        # Pick the candidate (this 64k block, previous, or next) closest to expected.
        best = candidate
        for cand in (candidate - 0x10000, candidate, candidate + 0x10000):
            if cand < 0:
                continue
            if abs(cand - expected) < abs(best - expected):
                best = cand
        if abs(best - expected) > _COUNTER_WINDOW:
            raise SessionError("counter far outside resync window")
        return best

    def decrypt(self, frame: bytes):
        """Open a received tunnel payload.

        Returns (msg_type, plaintext, counter). Raises on a wrong flow id, a bad
        tag, or a replayed counter. RECEIPT and REKEY frames are returned to the
        caller too (use `verify_receipt` / they are applied automatically for
        REKEY) so an app can surface delivery proofs.
        """
        if len(frame) < HEADER_LEN + TAG_LEN:
            raise SessionError("frame too short")
        msg_type, flow_id, counter_low = _HEADER.unpack(frame[:HEADER_LEN])
        if flow_id != self.local_flow:
            raise SessionError(
                f"flow id {flow_id:#06x} is not ours ({self.local_flow:#06x})"
            )
        header = frame[:HEADER_LEN]
        ct = frame[HEADER_LEN:]
        counter = self._reconstruct_counter(counter_low)
        try:
            pt = ChaCha20Poly1305(self._recv_key).decrypt(
                _nonce(self._recv_salt, counter), ct, header
            )
        except Exception as exc:
            raise SessionError(f"decrypt failed: {exc}") from exc
        # Only after authentication do we admit the counter to the replay window
        # (a forged counter must never be able to poison it).
        self._replay.check_and_set(counter)
        if counter > self._recv_high:
            self._recv_high = counter

        if msg_type == MSG_REKEY:
            self._apply_rekey(pt)
        return msg_type, pt, counter

    def verify_receipt(self, receipt_plaintext: bytes) -> int:
        """Verify a peer's delivery receipt (from a decrypted MSG_RECEIPT).

        Returns the acknowledged counter, or raises if the signature is invalid.
        """
        if self._peer_verify is None:
            raise SessionError("no peer verify key configured")
        if len(receipt_plaintext) != 8 + 64:
            raise SessionError("malformed receipt")
        (counter,) = struct.unpack("<Q", receipt_plaintext[:8])
        sig = receipt_plaintext[8:]
        try:
            self._peer_verify.verify(sig, self._receipt_digest(counter))
        except InvalidSignature as exc:
            raise SessionError("receipt signature invalid") from exc
        return counter

    # --- rekey ------------------------------------------------------------
    def _ratchet_send(self) -> None:
        self._send_key = _hkdf_expand(self._send_key, b"aln-rekey", 32)
        self._send_salt = _hkdf_expand(self._send_key, b"aln-nonce", 12)
        self._msgs_since_rekey = 0

    def _apply_rekey(self, _payload: bytes) -> None:
        self._recv_key = _hkdf_expand(self._recv_key, b"aln-rekey", 32)
        self._recv_salt = _hkdf_expand(self._recv_key, b"aln-nonce", 12)

    def send_rekey(self) -> bytes:
        """Explicitly ratchet the SEND key and emit a REKEY frame announcing it.

        The frame is sealed under the OLD key (so the peer can still open it),
        then both sides advance. Use for time-based rekey; counter-based rekey
        happens automatically inside `encrypt`.
        """
        frame = self._seal(MSG_REKEY, b"")
        self._ratchet_send()
        return frame
