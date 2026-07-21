package sign

import (
	"crypto/ed25519"
	"testing"
)

// FuzzVerifyControl throws arbitrary bytes at the control-frame verifier — the
// Go mirror of lib/mesh/control.cpp's ctrl_verify. VerifyControl parses the
// message BEFORE (and after) the signature check, so it must never panic on
// malformed input: a truncated header, a bad command, an inconsistent length,
// or garbage where the signature should be. This is the controller's exposure
// to bytes coming back off the mesh.
//
//	go test ./internal/sign -run x -fuzz FuzzVerifyControl
func FuzzVerifyControl(f *testing.F) {
	priv := KeyFromSeed(interopSeed())
	pub := priv.Public().(ed25519.PublicKey)

	// Seed with well-formed frames of every command shape so the fuzzer starts
	// from valid inputs and mutates outward.
	var target NodeID
	target[0] = 0x11
	var victim NodeID
	victim[0] = 0x22
	if m, err := BuildControl(CmdPower, target, 14, 7, priv); err == nil {
		f.Add(m, []byte(pub), uint32(0))
	}
	if m, err := BuildBlock(CmdBlock, target, victim, 30, 8, priv); err == nil {
		f.Add(m, []byte(pub), uint32(0))
	}
	if m, err := BuildRetune(target, RetuneCfg{FreqHz: 906875000, SF: 11}, 9, priv); err == nil {
		f.Add(m, []byte(pub), uint32(0))
	}
	f.Add([]byte{}, []byte(pub), uint32(0))
	f.Add([]byte{CtrlVer, CmdPower}, []byte(pub), uint32(0))

	f.Fuzz(func(t *testing.T, msg, pubBytes []byte, minCounter uint32) {
		// ed25519.Verify panics on a wrong-size key, so normalise as the real
		// caller does (keys come from a fixed-size keystore, never the wire).
		if len(pubBytes) != ed25519.PublicKeySize {
			return
		}
		pub := ed25519.PublicKey(pubBytes)

		// Must not panic, and must be self-consistent: a returned command's
		// counter is always strictly above the floor it was checked against.
		cmd, err := VerifyControl(msg, pub, minCounter)
		if err == nil && cmd.Counter <= minCounter {
			t.Fatalf("accepted counter %d <= floor %d", cmd.Counter, minCounter)
		}
	})
}
