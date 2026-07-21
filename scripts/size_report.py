#!/usr/bin/env python3
"""Flash/RAM size tracking for CI (handoff plan Task 0).

Parses PlatformIO build output (the `RAM:`/`Flash:` lines `pio run` prints per
environment) and checks each environment against the budgets recorded in
docs/size-budget.md. Using pio's own numbers -- rather than re-deriving them
from the .elf -- keeps this report bit-identical to what every developer sees
locally, including PlatformIO's ESP32-specific flash accounting.

Usage (CI):
    pio run -e wiscore_rak4631 ... 2>&1 | tee build.log
    python scripts/size_report.py build.log [more.log ...]

Behaviour:
  * Emits a per-env summary table to stdout and, when $GITHUB_STEP_SUMMARY is
    set, into the GitHub Actions job summary.
  * Exits 1 if any env exceeds its flash or RAM budget.
  * An env whose budget row is `TBD` is report-only (warned, never fails):
    that's the bootstrap state for a newly added board -- record its first CI
    numbers in docs/size-budget.md to arm the check.
  * An env that appears in the budget table but not in any log is an error
    (guards against a build step being silently dropped from the workflow).
"""

import os
import re
import sys

BUDGET_MD = os.path.join(os.path.dirname(__file__), "..", "docs", "size-budget.md")

# pio marks the start of each env with "Processing <env> (...)" and prints e.g.
#   RAM:   [==        ]  26.9% (used 67020 bytes from 248832 bytes)
#   Flash: [====      ]  35.6% (used 290084 bytes from 815104 bytes)
RE_ENV = re.compile(r"Processing ([A-Za-z0-9_]+) \(")
RE_SIZE = re.compile(
    r"(RAM|Flash):\s+\[[^\]]*\]\s+[0-9.]+% \(used (\d+) bytes from (\d+) bytes\)"
)
# Budget rows in docs/size-budget.md:
#   | env | flash budget | ram budget | baseline flash | baseline ram | date |
RE_BUDGET_ROW = re.compile(r"^\|\s*`?([A-Za-z0-9_]+)`?\s*\|(.*)\|\s*$")


def parse_logs(paths):
    """Return {env: {"RAM": (used, total), "Flash": (used, total)}}."""
    usage = {}
    env = None
    for path in paths:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = RE_ENV.search(line)
                if m:
                    env = m.group(1)
                    continue
                m = RE_SIZE.search(line)
                if m and env:
                    usage.setdefault(env, {})[m.group(1)] = (
                        int(m.group(2)),
                        int(m.group(3)),
                    )
    return usage


def parse_budgets(path):
    """Return {env: {"flash": int|None, "ram": int|None}} from the budget doc.

    None means TBD (report-only). Envs not listed at all are ignored by the
    check (e.g. `native`, `compile_check`).
    """
    budgets = {}
    with open(path) as fh:
        for line in fh:
            m = RE_BUDGET_ROW.match(line.strip())
            if not m:
                continue
            env = m.group(1)
            cells = [c.strip() for c in m.group(2).split("|")]
            if len(cells) < 2 or env in ("env", "---"):
                continue

            def num(cell):
                cell = cell.replace(",", "").replace("`", "")
                return int(cell) if cell.isdigit() else None

            budgets[env] = {"flash": num(cells[0]), "ram": num(cells[1])}
    return budgets


def fmt_kib(n):
    return f"{n} ({n / 1024:.1f} KiB)"


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    usage = parse_logs(argv[1:])
    budgets = parse_budgets(BUDGET_MD)

    rows = []
    failures = []
    warnings = []

    for env, budget in sorted(budgets.items()):
        if env not in usage:
            failures.append(
                f"{env}: listed in docs/size-budget.md but absent from build "
                f"logs -- is its build step missing from the workflow?"
            )
            rows.append((env, "missing", "", "missing", "", ":x:"))
            continue
        flash_used, flash_total = usage[env].get("Flash", (0, 0))
        ram_used, ram_total = usage[env].get("RAM", (0, 0))
        status = ":white_check_mark:"

        def check(kind, used, cap):
            nonlocal status
            if cap is None:
                warnings.append(
                    f"{env}: {kind} budget is TBD (used {used}); record it in "
                    f"docs/size-budget.md to arm the check"
                )
                if status != ":x:":
                    status = ":warning: TBD"
            elif used > cap:
                failures.append(
                    f"{env}: {kind} {used} bytes exceeds budget {cap} "
                    f"(+{used - cap})"
                )
                status = ":x:"

        check("flash", flash_used, budget["flash"])
        check("RAM", ram_used, budget["ram"])
        rows.append(
            (
                env,
                f"{flash_used} / {budget['flash'] or 'TBD'}",
                f"{100 * flash_used / flash_total:.1f}% of chip",
                f"{ram_used} / {budget['ram'] or 'TBD'}",
                f"{100 * ram_used / ram_total:.1f}% of chip",
                status,
            )
        )

    # Envs built but not budgeted: show them (informational) so nothing hides.
    for env in sorted(set(usage) - set(budgets)):
        flash_used, flash_total = usage[env].get("Flash", (0, 0))
        ram_used, ram_total = usage[env].get("RAM", (0, 0))
        rows.append(
            (
                env,
                f"{flash_used} / (unbudgeted)",
                f"{100 * flash_used / flash_total:.1f}% of chip",
                f"{ram_used} / (unbudgeted)",
                f"{100 * ram_used / ram_total:.1f}% of chip",
                "ℹ️",
            )
        )

    header = ("env", "flash used / budget", "flash", "RAM used / budget", "RAM", "ok")
    md = ["### Firmware size report", ""]
    md.append("| " + " | ".join(header) + " |")
    md.append("|" + "---|" * len(header))
    for r in rows:
        md.append("| `" + r[0] + "` | " + " | ".join(r[1:]) + " |")
    if warnings:
        md += ["", "**Warnings:**"] + [f"- {w}" for w in warnings]
    if failures:
        md += ["", "**Budget failures:**"] + [f"- {f}" for f in failures]
    report = "\n".join(md)

    print(report)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as fh:
            fh.write(report + "\n")

    if failures:
        print(
            "\nSize budget exceeded. If the growth is intentional and "
            "justified, raise the budget in docs/size-budget.md in the same "
            "commit and explain why in the table's notes.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
