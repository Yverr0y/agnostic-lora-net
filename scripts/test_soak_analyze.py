"""Tests for scripts/soak_analyze.py (the idle-power soak verifier).

    python3 -m unittest scripts.test_soak_analyze     (from repo root)

Uses synthetic console logs shaped exactly like the firmware's output, so the
metric extraction and the pass/fail gate are exercised without hardware.
"""

import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import soak_analyze as sa  # noqa: E402


def make_log(n=1200, beacon_every=10, miss_prob=0.0, mv0=4100, drain=3.0,
             stall_at=None, seed=0):
    """Deterministic synthetic node log. `miss_prob` drops beacon RX lines."""
    # Simple LCG so results are reproducible without importing random state.
    state = seed + 1
    def rnd():
        nonlocal state
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        return state / 0x7FFFFFFF

    lines = []
    up = 0
    seqs = {"8EA09546": 0, "1FAE0DBD": 0}
    for i in range(n):
        up += 3
        if stall_at is not None and i == stall_at:
            up += 40
        mv = int(mv0 - drain * (up / 3600.0))
        lines.append(f"[hb] up={up}s  node=DEADBEEF nbrs=2 routes=3 txq=0 stk=3900 batt={mv}mV/80%")
        if up % beacon_every == 0:
            for src in seqs:
                seqs[src] += 1
                if rnd() >= miss_prob:
                    lines.append(f"[RX] beacon  src={src} seq={seqs[src]} up={up}s  rssi=-42.0 snr=9.0")
    return "\n".join(lines) + "\n"


def stats_from(text, name="t"):
    s = sa.NodeStats(name)
    for line in io.StringIO(text):
        s.feed(line)
    return s


class TestMetrics(unittest.TestCase):
    def test_clean_log_has_no_misses(self):
        s = stats_from(make_log(miss_prob=0.0))
        self.assertEqual(s.beacon_miss_ratio(), 0.0)
        self.assertEqual(s.max_hb_gap_s(), 3)
        self.assertEqual(s.runts, 0)
        self.assertEqual(len(s.beacons), 2)

    def test_miss_ratio_tracks_drops(self):
        s = stats_from(make_log(miss_prob=0.2, seed=3))
        mr = s.beacon_miss_ratio()
        self.assertGreater(mr, 0.1)
        self.assertLess(mr, 0.3)

    def test_battery_drain_slope(self):
        # Large per-hour drop so integer-mV rounding of the endpoints is noise.
        s = stats_from(make_log(n=2000, drain=60.0))
        d = s.batt_drain_mv_per_h()
        self.assertAlmostEqual(d, 60.0, delta=1.0)

    def test_heartbeat_stall_detected(self):
        s = stats_from(make_log(stall_at=300))
        self.assertGreaterEqual(s.max_hb_gap_s(), 40)

    def test_version_drops_and_runts(self):
        s = stats_from("[hb] up=3s stk=3900\n[RX] runt frame, dropped\n[ver] drops=5 last=1 supported=2\n")
        self.assertEqual(s.runts, 1)
        self.assertEqual(s.max_verdrop, 5)


class TestGate(unittest.TestCase):
    def test_ok_when_sleep_matches_control(self):
        control = stats_from(make_log(miss_prob=0.01, drain=3.0, seed=1), "control")
        sleep = stats_from(make_log(miss_prob=0.012, drain=1.5, seed=2), "sleep")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sa.compare(control, sleep)
        self.assertEqual(rc, 0)

    def test_regression_on_beacon_misses(self):
        control = stats_from(make_log(miss_prob=0.01, seed=1), "control")
        sleep = stats_from(make_log(miss_prob=0.15, seed=2), "sleep")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sa.compare(control, sleep)
        self.assertEqual(rc, 1)

    def test_regression_on_heartbeat_stall(self):
        control = stats_from(make_log(miss_prob=0.01, seed=1), "control")
        sleep = stats_from(make_log(miss_prob=0.01, stall_at=200, seed=2), "sleep")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sa.compare(control, sleep)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
