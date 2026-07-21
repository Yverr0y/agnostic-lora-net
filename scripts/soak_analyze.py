#!/usr/bin/env python3
"""Soak-test analyzer for the idle-power change (handoff plan Task 4).

The acceptance bar for light-sleep is "zero reliability regression vs a
non-sleeping control, over a 24 h multi-hop soak." That comparison is the bulk
of the task, and this tool is how you make it objective: point it at the console
logs of a SLEEP-enabled node and a non-sleeping CONTROL node captured over the
same soak, and it diffs the reliability indicators the firmware already emits —
no firmware change, no extra instrumentation.

Metrics (all from lines the node prints today):
  * beacon reception gaps — from `[RX] beacon src=<id> seq=<n> ...` (trace on):
    per neighbour, missed = (max_seq - min_seq + 1) - received. This is the
    direct "did sleeping make us miss packets?" signal.
  * heartbeat cadence — from `[hb] up=<s> ...`: the loop should still beat every
    ~3 s; long gaps mean the node stalled.
  * battery drain — from `batt=<mv>mV` on the heartbeat: mV/hour, the plan's
    accepted proxy for idle current when no PPK2/INA meter is available.
  * error lines — `runt frame`, `[ver] drops=`: should not appear/grow.

Exit status is non-zero if the sleep node regressed beyond tolerance, so this
can gate a soak run.

Usage:
    python3 scripts/soak_analyze.py --control control.log --sleep sleep.log
    python3 scripts/soak_analyze.py --report one.log          # single-log summary
"""

import argparse
import re
import sys

RE_HB = re.compile(r"\[hb\] up=(\d+)s")
RE_HB_BATT = re.compile(r"\[hb\] up=(\d+)s.*batt=(\d+)mV")
RE_BEACON_RX = re.compile(
    r"\[RX\] beacon\s+src=([0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}) seq=(\d+) up=(\d+)s"
)
RE_RUNT = re.compile(r"runt frame")
RE_VERDROP = re.compile(r"\[ver\] drops=(\d+)")


class NodeStats:
    def __init__(self, name):
        self.name = name
        self.hb_uptimes = []          # uptime seconds seen on heartbeats
        self.batt = []                # (uptime_s, mv)
        self.beacons = {}             # src -> set of seq seen
        self.runts = 0
        self.max_verdrop = 0

    def feed(self, line):
        m = RE_HB.search(line)
        if m:
            self.hb_uptimes.append(int(m.group(1)))
        mb = RE_HB_BATT.search(line)
        if mb:
            self.batt.append((int(mb.group(1)), int(mb.group(2))))
        m = RE_BEACON_RX.search(line)
        if m:
            src, seq = m.group(1).upper(), int(m.group(2))
            self.beacons.setdefault(src, set()).add(seq)
        if RE_RUNT.search(line):
            self.runts += 1
        m = RE_VERDROP.search(line)
        if m:
            self.max_verdrop = max(self.max_verdrop, int(m.group(1)))

    # --- derived metrics --------------------------------------------------
    def beacon_miss_ratio(self):
        """Fraction of expected neighbour beacons that were missed (0..1)."""
        expected = received = 0
        for seqs in self.beacons.values():
            if len(seqs) < 2:
                continue
            lo, hi = min(seqs), max(seqs)
            expected += hi - lo + 1
            received += len(seqs)
        if expected == 0:
            return None
        return (expected - received) / expected

    def max_hb_gap_s(self):
        if len(self.hb_uptimes) < 2:
            return None
        ordered = sorted(self.hb_uptimes)
        return max(b - a for a, b in zip(ordered, ordered[1:]))

    def batt_drain_mv_per_h(self):
        if len(self.batt) < 2:
            return None
        (t0, v0), (t1, v1) = self.batt[0], self.batt[-1]
        dt_h = (t1 - t0) / 3600.0
        if dt_h <= 0:
            return None
        return (v0 - v1) / dt_h

    def duration_h(self):
        if len(self.hb_uptimes) < 2:
            return 0.0
        return (max(self.hb_uptimes) - min(self.hb_uptimes)) / 3600.0

    def summary(self):
        mr = self.beacon_miss_ratio()
        return {
            "node": self.name,
            "duration_h": round(self.duration_h(), 2),
            "heartbeats": len(self.hb_uptimes),
            "max_hb_gap_s": self.max_hb_gap_s(),
            "neighbours_heard": len(self.beacons),
            "beacon_miss_ratio": None if mr is None else round(mr, 4),
            "batt_drain_mV_per_h": self.batt_drain_mv_per_h(),
            "runt_frames": self.runts,
            "version_drops": self.max_verdrop,
        }


def load(path, name):
    stats = NodeStats(name)
    with open(path, errors="replace") as fh:
        for line in fh:
            stats.feed(line)
    return stats


def print_summary(s):
    for k, v in s.summary().items():
        print(f"  {k:22} {v}")


# Tolerances for the pass/fail gate (tune per bench).
MISS_RATIO_ABS_TOL = 0.02   # sleep node may miss at most 2 pp more beacons than control
HB_GAP_MAX_S = 15           # a healthy ~3 s heartbeat should never gap past this


def compare(control, sleep):
    print(f"=== control: {control.name} ===")
    print_summary(control)
    print(f"=== sleep:   {sleep.name} ===")
    print_summary(sleep)

    problems = []

    cm, sm = control.beacon_miss_ratio(), sleep.beacon_miss_ratio()
    if cm is None or sm is None:
        problems.append(
            "beacon miss ratio unavailable (need `trace on` beacon RX lines on "
            "both nodes over the soak)"
        )
    elif sm > cm + MISS_RATIO_ABS_TOL:
        problems.append(
            f"beacon miss ratio regressed: sleep {sm:.4f} vs control {cm:.4f} "
            f"(> +{MISS_RATIO_ABS_TOL})"
        )

    sg = sleep.max_hb_gap_s()
    if sg is not None and sg > HB_GAP_MAX_S:
        problems.append(f"sleep node heartbeat gap {sg}s exceeds {HB_GAP_MAX_S}s (loop stalled?)")

    if sleep.runts > control.runts * 2 + 5:
        problems.append(f"sleep node runt frames {sleep.runts} >> control {control.runts}")

    cd, sd = control.batt_drain_mv_per_h(), sleep.batt_drain_mv_per_h()
    print("\n=== verdict ===")
    if cd is not None and sd is not None:
        delta = cd - sd
        print(f"  battery drain: control {cd:.1f} mV/h, sleep {sd:.1f} mV/h "
              f"({'sleep saves ' + format(delta, '.1f') + ' mV/h' if delta > 0 else 'no saving'})")
        if delta <= 0:
            print("  NOTE: no measured battery saving — expected several mA -> ~half draw; "
                  "check the node was truly unattended (USB detaches the sleep path).")

    if problems:
        print("  RESULT: REGRESSION")
        for p in problems:
            print(f"   - {p}")
        return 1
    print("  RESULT: OK — no reliability regression within tolerance")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--control", help="console log of the non-sleeping control node")
    ap.add_argument("--sleep", help="console log of the sleep-enabled node")
    ap.add_argument("--report", help="single log to summarise (no comparison)")
    args = ap.parse_args(argv[1:])

    if args.report:
        print_summary(load(args.report, args.report))
        return 0
    if not (args.control and args.sleep):
        ap.error("provide --control and --sleep (or --report for a single log)")
    return compare(load(args.control, args.control), load(args.sleep, args.sleep))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
