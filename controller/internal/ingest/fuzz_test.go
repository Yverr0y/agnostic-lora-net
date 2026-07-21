package ingest

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseLine feeds arbitrary console text at the line parser. ParseLine
// ingests untrusted node output (a compromised or malfunctioning node, or line
// noise on the serial link), so it must never panic and must stay internally
// consistent: when it claims a line is structured (ok == true) the Event's maps
// are non-nil and its Kind is a real one.
//
//	go test ./internal/ingest -run x -fuzz FuzzParseLine
func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"node 0011223344556677889AABBCCDDEEFF00 neighbors=3 routes=5 blocked=1 name=hub",
		"[blocked] 0011223344556677889AABBCCDDEEFF00 00FF00FF00FF00FF00FF00FF00FF00FF",
		"fw 0.15.0",
		"batt mv=3712 pct=88",
		"batt raw=612 UNCALIBRATED",
		"[rf] freq_hz=906875000 bw_hz=250000 sf=11 cr=5 power_dbm=14 sync=0x12 preamble=8",
		"nbr 00112233 q_rx=90 q_tx=85 rssi=-88 snr=7",
		"route dst=00112233 via=44556677 cost=12 hops=2",
		"[ctrl] ack 00112233 cmd=1 applied=14 provisional=0",
		"[batt] 00112233 mv=3650 pct=76 age=42s",
		"[status] 00112233 fw=0.15.0 up=1234min sf=11 pwr=14 batt=3650mV/76% mob=1 ble=0 name=n",
		"[ann] 00112233 pub=" + strings.Repeat("ab", 32) + " sig=ok",
		"[RX] type=5 src=00112233 seq=7 len=42",
		"",
		"   ",
		"garbage that matches nothing at all",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		e, ok := ParseLine(line)
		if !ok {
			return
		}
		if e.Kind == KindUnknown {
			t.Fatalf("ok=true but Kind=Unknown for %q", line)
		}
		if e.Num == nil || e.Str == nil {
			t.Fatalf("ok=true but nil maps for %q", line)
		}
		// Normalised ids must be valid hex of a supported width — a parser that
		// emitted a malformed id would corrupt the topology model downstream.
		for _, id := range append([]string{e.ID, e.Peer, e.Dst}, e.Blocked...) {
			if id == "" {
				continue
			}
			if l := len(id); l != 8 && l != 32 {
				t.Fatalf("id %q has width %d (want 8 or 32) from %q", id, l, line)
			}
		}
		// The parser must not invent invalid UTF-8 in free-form captures.
		if !utf8.ValidString(e.Raw) && utf8.ValidString(line) {
			t.Fatalf("Raw became invalid UTF-8 from valid input %q", line)
		}
	})
}
