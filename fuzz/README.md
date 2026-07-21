# Fuzzing the RX parsers

Anyone with a radio can transmit arbitrary bytes at these nodes, and anyone
with a serial cable can type arbitrary bytes at the console. Every decode path
in `lib/mesh` therefore has a libFuzzer harness here, built with clang +
ASan/UBSan directly against the portable sources — no PlatformIO, no firmware
flash cost (fixes only).

| harness | covers | style |
|---|---|---|
| `fuzz_announce` | `announce_codec`: deserialize, verify (body/tail splits) | single buffer + round-trip |
| `fuzz_control` | `control`: `ctrl_verify` (pre-sig parse + sig path), ACK parse | pubkey ‖ msg split |
| `fuzz_telemetry` | `telemetry`: `telem_parse` (BATT/QUERY/REPLY) | single buffer + rebuild round-trip |
| `fuzz_loc` | `locator_dir`: `loc_parse` | single buffer + rebuild round-trip |
| `fuzz_sar` | `sar`: reassembler state machine, NACK/DONE parse | **stateful** op-sequence |
| `fuzz_arq` | `link_arq`: track/ack/tick engine | **stateful** op-sequence |
| `fuzz_kiss` | `kiss.h`: streaming decoder + encode round-trip | byte stream |
| `fuzz_frame` | on-air frame dispatch (mirrors `on_rx` in `src/main.cpp`) | whole frame |

Go-side fuzzing lives with the Go code (native `go test -fuzz`):
`controller/internal/sign` (control verify) and `controller/internal/ingest`
(console-stream line parser).

## Running

```sh
cd fuzz
make            # build all harnesses (needs clang with libFuzzer)
make run-all SECS=60
make run T=sar SECS=600
make repro T=sar F=crash-<hash>   # replay a finding
```

`corpus/` is the checked-in seed + minimized corpus (regenerate seeds with
`make seeds`; the seeds are produced by the library's own builders and double
as golden wire vectors). CI runs every harness for a short bounded time on
each PR and a longer pass nightly (`.github/workflows/fuzz.yml`).

## Rules

- **Every crash/UB fix gets a regression test** in `test/test_*` with the
  offending bytes, in the same commit as the fix.
- Harnesses assert invariants, not just memory-safety: anything a parser
  accepts must rebuild + reparse cleanly (`__builtin_trap()` on violation).
- Keep harness input caps generous (2–8 KiB) — real frames are ≤255 B, but the
  parsers must not *depend* on that.

## Bounds-checking audit (Task 1 item 6)

All `lib/mesh` parsers follow one of two consistent styles: up-front
`len < need` precheck against declared counts (announce, control, sar), or
incremental cursor checks before each variable-length section (telemetry,
locator). Both are length-checked at every multi-byte read via the shared
`get_u16`/`get_u32`/`nid_read` helpers; no ad-hoc pointer arithmetic without a
preceding bound was found. A shared `ByteReader` was considered (plan
suggestion) and deliberately not introduced: the existing style is uniform,
the parsers are small, and a refactor of working, fuzzed code would add churn
and re-verification cost for no measured flash win.
