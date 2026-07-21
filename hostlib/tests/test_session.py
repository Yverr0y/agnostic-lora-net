"""Tests for aln_session: handshake, transport, replay, resync, receipts, rekey.

    cd hostlib && python3 -m pytest        (or: python3 -m unittest)

Written with unittest so it runs with no extra tooling; pytest also collects it.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aln_session import (  # noqa: E402
    Identity,
    Initiator,
    Responder,
    Session,
    SessionError,
    ReplayError,
    OVERHEAD,
    MSG_DATA,
    MSG_RECEIPT,
    handshake_in_memory,
)
from aln_session.noise import HandshakeError, NoiseHandshake  # noqa: E402


def fixed_identity(tag: int) -> Identity:
    return Identity.from_seeds(bytes([tag]) * 32, bytes([tag ^ 0xFF]) * 32)


class TestHandshake(unittest.TestCase):
    def test_ik_roundtrip_and_keys_agree(self):
        a, b = fixed_identity(1), fixed_identity(2)
        i = Initiator(a, remote_static=b.static_pub(),
                      remote_verify_key=b.signing.public_key())
        r = Responder(b, remote_verify_key=a.signing.public_key())
        sa, sb = handshake_in_memory(i, r)
        # Flow ids cross over correctly.
        self.assertEqual(sa.remote_flow, sb.local_flow)
        self.assertEqual(sb.remote_flow, sa.local_flow)
        self.assertEqual(sa.transcript_id, sb.transcript_id)

    def test_xx_first_contact(self):
        a, b = fixed_identity(3), fixed_identity(4)
        i = Initiator(a, remote_verify_key=b.signing.public_key())  # no remote_static -> XX
        r = Responder(b, remote_verify_key=a.signing.public_key(), pattern="XX")
        sa, sb = handshake_in_memory(i, r)
        msg = sa.encrypt(b"first contact")
        self.assertEqual(sb.decrypt(msg)[1], b"first contact")

    def test_ik_wrong_responder_static_fails(self):
        a, b, imposter = fixed_identity(5), fixed_identity(6), fixed_identity(7)
        # Initiator thinks it's talking to `imposter` but responder holds b's key.
        i = Initiator(a, remote_static=imposter.static_pub())
        r = Responder(b)
        m1 = i.first_message()
        with self.assertRaises(HandshakeError):
            r.handle_first(m1)   # es/ss DH mismatch -> AEAD failure on the payload


class TestTransport(unittest.TestCase):
    def setUp(self):
        self.a, self.b = fixed_identity(10), fixed_identity(11)
        i = Initiator(self.a, remote_static=self.b.static_pub(),
                      remote_verify_key=self.b.signing.public_key())
        r = Responder(self.b, remote_verify_key=self.a.signing.public_key())
        self.sa, self.sb = handshake_in_memory(i, r)

    def test_roundtrip_both_directions(self):
        f = self.sa.encrypt(b"a->b")
        self.assertEqual(self.sb.decrypt(f), (MSG_DATA, b"a->b", 0))
        g = self.sb.encrypt(b"b->a")
        self.assertEqual(self.sa.decrypt(g), (MSG_DATA, b"b->a", 0))

    def test_overhead_within_budget(self):
        payload = b"x" * 40
        frame = self.sa.encrypt(payload)
        self.assertEqual(len(frame) - len(payload), OVERHEAD)
        self.assertLessEqual(OVERHEAD, 40)   # plan's ceiling

    def test_wrong_flow_id_rejected(self):
        frame = bytearray(self.sa.encrypt(b"hi"))
        frame[1] ^= 0xFF   # corrupt flow id
        with self.assertRaises(SessionError):
            self.sb.decrypt(bytes(frame))

    def test_tampered_ciphertext_rejected(self):
        frame = bytearray(self.sa.encrypt(b"hello"))
        frame[-1] ^= 0x01
        with self.assertRaises(SessionError):
            self.sb.decrypt(bytes(frame))

    def test_replay_rejected(self):
        frame = self.sa.encrypt(b"once")
        self.sb.decrypt(frame)
        with self.assertRaises(ReplayError):
            self.sb.decrypt(frame)   # exact replay

    def test_out_of_order_within_window_ok(self):
        f0 = self.sa.encrypt(b"m0")
        f1 = self.sa.encrypt(b"m1")
        f2 = self.sa.encrypt(b"m2")
        # Deliver 2, 0, 1 — all accepted once, none twice.
        self.assertEqual(self.sb.decrypt(f2)[1], b"m2")
        self.assertEqual(self.sb.decrypt(f0)[1], b"m0")
        self.assertEqual(self.sb.decrypt(f1)[1], b"m1")
        with self.assertRaises(ReplayError):
            self.sb.decrypt(f1)

    def test_counter_resync_after_loss(self):
        # Drop a large run of sender messages; the low-16-bit counter still
        # reconstructs and the next delivered frame decrypts.
        for _ in range(5000):
            self.sa.encrypt(b"lost")
        frame = self.sa.encrypt(b"after gap")
        kind, msg, ctr = self.sb.decrypt(frame)
        self.assertEqual(msg, b"after gap")
        self.assertEqual(ctr, 5000)

    def test_counter_wraps_16_bits(self):
        # Cross the 16-bit boundary while the receiver keeps pace (a frame every
        # 1000, gaps well within the resync window). Reconstruction must pick the
        # right 64k block on both sides of the wrap.
        last = -1
        for n in range(70001):
            frame = self.sa.encrypt(b"past wrap")
            if n % 1000 == 0:
                _, msg, ctr = self.sb.decrypt(frame)
                self.assertEqual(msg, b"past wrap")
                self.assertEqual(ctr, n)   # correct full counter across the wrap
                last = ctr
        self.assertGreater(last, 0xFFFF)   # we really did cross the boundary

    def test_gap_beyond_window_rejected(self):
        # A loss burst larger than the 16-bit field can disambiguate is rejected
        # cleanly (never mis-decoded to a wrong counter).
        for _ in range(40000):
            self.sa.encrypt(b"lost")
        frame = self.sa.encrypt(b"too far")
        with self.assertRaises(SessionError):
            self.sb.decrypt(frame)


class TestReceipts(unittest.TestCase):
    def setUp(self):
        self.a, self.b = fixed_identity(20), fixed_identity(21)
        i = Initiator(self.a, remote_static=self.b.static_pub(),
                      remote_verify_key=self.b.signing.public_key())
        r = Responder(self.b, remote_verify_key=self.a.signing.public_key())
        self.sa, self.sb = handshake_in_memory(i, r)

    def test_receipt_roundtrip(self):
        frame = self.sa.encrypt(b"deliver me")
        kind, msg, ctr = self.sb.decrypt(frame)
        receipt = self.sb.make_receipt(ctr)          # b signs
        rkind, rp, _ = self.sa.decrypt(receipt)
        self.assertEqual(rkind, MSG_RECEIPT)
        self.assertEqual(self.sa.verify_receipt(rp), ctr)  # a verifies b's proof

    def test_forged_receipt_rejected(self):
        frame = self.sa.encrypt(b"x")
        _, _, ctr = self.sb.decrypt(frame)
        receipt = self.sb.make_receipt(ctr)
        _, rp, _ = self.sa.decrypt(receipt)
        forged = bytearray(rp)
        forged[-1] ^= 0x01   # break the signature
        with self.assertRaises(SessionError):
            self.sa.verify_receipt(bytes(forged))

    def test_receipt_bound_to_this_session(self):
        # A receipt from one session must not verify against another (transcript
        # id binds it): build a second, independent session and cross-check.
        a2, b2 = fixed_identity(30), fixed_identity(31)
        i2 = Initiator(a2, remote_static=b2.static_pub(),
                       remote_verify_key=b2.signing.public_key())
        r2 = Responder(b2, remote_verify_key=a2.signing.public_key())
        sa2, sb2 = handshake_in_memory(i2, r2)

        _, _, ctr = self.sb.decrypt(self.sa.encrypt(b"y"))
        receipt_pt = None
        _, receipt_pt, _ = self.sa.decrypt(self.sb.make_receipt(ctr))
        # sa2 has a different transcript id, so the digest differs -> reject.
        with self.assertRaises(SessionError):
            sa2.verify_receipt(receipt_pt)


class TestRekey(unittest.TestCase):
    def _pair(self, rekey_after):
        a, b = fixed_identity(40), fixed_identity(41)
        i = Initiator(a, remote_static=b.static_pub(), rekey_after=rekey_after)
        r = Responder(b, rekey_after=rekey_after)
        return handshake_in_memory(i, r)

    def test_explicit_rekey_keeps_traffic_flowing(self):
        sa, sb = self._pair(rekey_after=8)
        # Traffic before rekey.
        self.assertEqual(sb.decrypt(sa.encrypt(b"pre"))[1], b"pre")
        # Rekey: sa emits a REKEY frame under the old key; sb applies on decrypt.
        rk = sa.send_rekey()
        kind, _, _ = sb.decrypt(rk)
        # Traffic after rekey still decrypts (both ratcheted the a->b key).
        self.assertEqual(sb.decrypt(sa.encrypt(b"post"))[1], b"post")

    def test_rekey_due_flag(self):
        sa, sb = self._pair(rekey_after=3)
        self.assertFalse(sa.rekey_due)
        for _ in range(3):
            sa.encrypt(b".")
        self.assertTrue(sa.rekey_due)
        sa.send_rekey()
        self.assertFalse(sa.rekey_due)   # counter-since-rekey reset


if __name__ == "__main__":
    unittest.main()
