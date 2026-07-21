"""Drive a full handshake + flow-id negotiation, then hand back a Session.

Flow ids are negotiated in the handshake payloads (the plan): each side proposes
the 2-byte label the OTHER should stamp on frames addressed to it — the same
idea as the firmware's 1-byte link aliases, but end-to-end. The steady-state
tunnel frame then addresses by 2-byte flow id instead of a 16-byte node id.

Both patterns are supported:
  * IK (`initiate`/`respond` with `remote_static`): 1-RTT, responder static
    known out of band (the normal contact case).
  * XX (no `remote_static`): first contact, 1.5-RTT, both statics exchanged.

The transport (the TCP bridge / tunnel) carries the raw handshake messages
verbatim; this module is transport-agnostic. `Initiator` and `Responder` expose
a small step API; `handshake_in_memory` wires two of them together for tests.
"""

from __future__ import annotations

import os
import struct

from .identity import Identity, load_static_pub
from .noise import NoiseHandshake
from .session import Session

_FLOW = struct.Struct("<H")


def _pick_flow() -> int:
    # 1..0xFFFE (0 and 0xFFFF reserved, mirroring the link-alias convention).
    return 1 + int.from_bytes(os.urandom(2), "little") % 0xFFFD


class Initiator:
    """Client side of a session handshake."""

    def __init__(
        self,
        identity: Identity,
        remote_static: bytes | None = None,
        remote_verify_key=None,
        local_flow: int | None = None,
        rekey_after: int = 4096,
    ):
        self.identity = identity
        self.local_flow = local_flow if local_flow is not None else _pick_flow()
        self._remote_verify = remote_verify_key
        self._rekey_after = rekey_after
        pattern = "IK" if remote_static else "XX"
        self.hs = NoiseHandshake(
            pattern,
            initiator=True,
            static=identity.static,
            remote_static_pub=load_static_pub(remote_static) if remote_static else None,
        )
        self.session: Session | None = None
        self.remote_flow: int | None = None

    def first_message(self, app_payload: bytes = b"") -> bytes:
        """Handshake message 1 (carries our proposed flow id)."""
        return self.hs.write_message(_FLOW.pack(self.local_flow) + app_payload)

    def final_message(self, response: bytes, app_payload: bytes = b"") -> bytes:
        """Consume message 2, emit message 3, and finalise the session.

        Returns (msg3_bytes, peer_app_payload). For IK there is no msg3, so the
        second element of the tuple is the peer payload and msg3 is b"".
        """
        peer = self.hs.read_message(response)
        (self.remote_flow,) = _FLOW.unpack(peer[:2])
        peer_app = peer[2:]
        msg3 = b""
        if not self.hs.finished:  # XX has a third message
            msg3 = self.hs.write_message(app_payload)
        self._build_session()
        return msg3, peer_app

    def _build_session(self) -> None:
        self.session = Session.from_handshake(
            self.hs,
            local_flow=self.local_flow,
            remote_flow=self.remote_flow,
            signing_key=self.identity.signing,
            peer_verify_key=self._remote_verify,
            rekey_after=self._rekey_after,
        )


class Responder:
    """Server side of a session handshake."""

    def __init__(
        self,
        identity: Identity,
        remote_verify_key=None,
        local_flow: int | None = None,
        rekey_after: int = 4096,
        pattern: str = "IK",
    ):
        self.identity = identity
        self.local_flow = local_flow if local_flow is not None else _pick_flow()
        self._remote_verify = remote_verify_key
        self._rekey_after = rekey_after
        self.hs = NoiseHandshake(pattern, initiator=False, static=identity.static)
        self.session: Session | None = None
        self.remote_flow: int | None = None

    def handle_first(self, message: bytes, app_payload: bytes = b""):
        """Consume message 1, emit message 2 (carries our flow id).

        Returns (msg2_bytes, peer_app_payload).
        """
        peer = self.hs.read_message(message)
        (self.remote_flow,) = _FLOW.unpack(peer[:2])
        peer_app = peer[2:]
        msg2 = self.hs.write_message(_FLOW.pack(self.local_flow) + app_payload)
        if self.hs.finished:  # IK completes here
            self._build_session()
        return msg2, peer_app

    def handle_final(self, message: bytes) -> bytes:
        """Consume the XX message 3 and finalise. Returns peer app payload."""
        peer_app = self.hs.read_message(message)
        self._build_session()
        return peer_app

    def _build_session(self) -> None:
        self.session = Session.from_handshake(
            self.hs,
            local_flow=self.local_flow,
            remote_flow=self.remote_flow,
            signing_key=self.identity.signing,
            peer_verify_key=self._remote_verify,
            rekey_after=self._rekey_after,
        )


def handshake_in_memory(
    initiator: Initiator, responder: Responder
) -> tuple[Session, Session]:
    """Run a complete handshake between two parties in-process (tests/bench).

    Returns (initiator_session, responder_session), both ready for traffic.
    """
    m1 = initiator.first_message()
    m2, _ = responder.handle_first(m1)
    m3, _ = initiator.final_message(m2)
    if m3:  # XX
        responder.handle_final(m3)
    assert initiator.session and responder.session
    return initiator.session, responder.session
