# hostlib — reusable host-side libraries

Host-side Python libraries for building on agnostic-LoRa-Net. These run on the
**bridge host** (RPi / PC / phone), never on a node — nothing here changes
firmware or the mobile app.

## `aln_session` — secure session layer for custom apps

For apps that speak the raw tunnel protocol (docs/tcp-bridge.md **Path B**) and
need end-to-end confidentiality, authentication, and delivery proofs without
bringing their own crypto stack.

> **Reticulum / LXMF apps do NOT need this.** If your app is a Reticulum client
> (Sideband, MeshChat, the native `reticulum-mobile-app`), use Reticulum's own
> crypto — it's already session-oriented (ECDH at link establishment) and its
> value is LXMF wire compatibility. Adding a second crypto stack there would
> break interop. This library is only for **non-Reticulum custom apps**.

### What it gives you

- **Noise handshake** (`IK` when you know the peer's static key out of band —
  the normal contact case, 1-RTT; `XX` for first contact) over vetted
  primitives: X25519 + ChaCha20-Poly1305 + HKDF-SHA256, Ed25519 for receipts.
  No hand-rolled crypto — everything is `cryptography`'s primitives; only the
  Noise state machine is ours, and it's interop- and tamper-tested.
- **Low-overhead transport**: `[1B type][2B flow-id][2B counter-low][ct][16B tag]`
  — **21 B overhead** per message (5 B framing + 16 B AEAD tag), well under the
  plan's 40 B ceiling. The 2-byte flow id replaces a 16-byte app-level id in the
  steady state.
- **Replay protection** (per-direction sliding window) and **counter resync**
  after loss (only 16 low bits on the wire; the full 64-bit counter is
  reconstructed, tolerating gaps up to ~32k messages).
- **Delivery proofs**: the recipient signs `hash(transcript_id ‖ counter)` with
  its Ed25519 identity key — equivalent to the mesh's cryptographic delivery
  proof, bound to the specific session.
- **Rekey**: an explicit HKDF ratchet (`send_rekey()` / `rekey_due`) the caller
  drives every N messages or T hours.

### Where it sits

The session frame is the opaque `[payload]` inside the tunnel envelope
`[addr_type][addr_len][node-id][payload]`. The node routes by the 16-byte node
id in the envelope (**zero firmware change**); the flow id and all crypto live
in the payload the backbone never inspects. See
`examples/session_over_tunnel.py` for the full wire path.

### Quick start

```python
from aln_session import Identity, Initiator, Responder, handshake_in_memory

alice, bob = Identity.generate(), Identity.generate()
i = Initiator(alice, remote_static=bob.static_pub(),
              remote_verify_key=bob.signing.public_key())   # IK
r = Responder(bob, remote_verify_key=alice.signing.public_key())
sa, sb = handshake_in_memory(i, r)          # in production the 2-3 handshake
                                            # messages ride the tunnel too

frame = sa.encrypt(b"hello over LoRa")      # -> put in a tunnel envelope, send
kind, msg, ctr = sb.decrypt(frame)          # (MSG_DATA, b"hello over LoRa", 0)
receipt = sb.make_receipt(ctr)              # signed delivery proof, sent back
_, rp, _ = sa.decrypt(receipt)
assert sa.verify_receipt(rp) == ctr
```

For a real bridge, drive `Initiator`/`Responder`'s step methods
(`first_message` / `handle_first` / `final_message` / `handle_final`) over the
tunnel instead of `handshake_in_memory`.

### Install & test

```sh
pip install cryptography          # the only dependency
cd hostlib && python3 -m unittest        # or: python3 -m pytest
python3 examples/session_over_tunnel.py  # end-to-end demo over the tunnel wire
```

### Security notes

- Static (X25519) and signing (Ed25519) keys are the endpoint's long-term
  identity. Exchange the public halves out of band (a signed announce, a contact
  QR, config) — the handshake authenticates against them.
- `IK` reveals nothing about the initiator to a passive observer beyond message
  sizes; the initiator's static key is sent encrypted. Use `XX` only when you
  can't know the responder's static key ahead of time.
- Nonces never repeat within a key: the per-direction salt is HKDF-derived and
  XORed with a strictly-increasing counter; rekey rotates the salt too.
- This layer secures the payload end to end; it does not hide traffic metadata
  (who talks to whom, when, how much) — that's inherent to the shared LoRa
  medium.
