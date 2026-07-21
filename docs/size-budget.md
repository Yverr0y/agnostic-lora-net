# Firmware size budget

CI fails any build whose flash or RAM usage exceeds the budgets below
(`scripts/size_report.py`, run at the end of the `firmware` job). The point is
that every flash-cost decision in the hardening plan is made with real numbers:
a change that grows a board past its budget must raise the budget *in the same
commit*, with a note explaining what bought the bytes.

Numbers are PlatformIO's own accounting (the `RAM:`/`Flash:` lines `pio run`
prints), so what CI checks is exactly what you see building locally.

## Budgets

Budget = baseline + 10%, rounded up to the next KiB. `TBD` rows are
report-only: CI prints the numbers but does not fail — record the first CI
numbers here (+10%) to arm the check for that board.

| env | flash budget (bytes) | RAM budget (bytes) | baseline flash | baseline RAM | baseline version |
|---|---|---|---|---|---|
| `wiscore_rak4631` | 319488 | 73728 | 290084 | 67020 | v0.15.0 |
| `xiao_nrf52` | 320512 | 74752 | 290556 | 67140 | v0.15.0 |
| `promicro` | 319488 | 74752 | 290244 | 67140 | v0.15.0 |
| `tracker_t1000_e` | TBD | TBD | — | — | — |
| `heltec_v4` | 472064 | 75776 | 428945 | 68000 | v0.15.0 |
| `xiao_esp32s3` | 476160 | 75776 | 432617 | 68268 | v0.15.0 |

Baselines were captured from the `main` CI build of v0.15.0
(commit `0fa0a37`, run 28237078384, 2026-06-26).

## Context

- The tightest targets are the nRF52840 boards: the s140 SoftDevice v7 is
  resident, leaving ~792 KiB of app flash, and the bootloader reserves the top
  region. At the v0.15.0 baseline the nRF52 builds sit at ~36% flash / ~27% RAM
  of what PlatformIO reports available — comfortable, but flash is the budget
  that guards against dependency creep (the ground rule is: no new firmware
  dependency without a flash-delta justification from these numbers).
- The ESP32-S3 boards have far more headroom; their budgets exist mainly to
  catch accidents (a debug format library, an unstripped table) rather than to
  ration bytes.
- RAM budgets guard `.data`+`.bss` growth. Note the nRF52 totals PlatformIO
  reports already exclude the SoftDevice's RAM carve-out.

## Raising a budget

1. Make the change; CI's "Firmware size report" step shows the new usage per
   board in the job summary.
2. If a budget trips and the growth is justified (per the handoff plan: only
   hardening, compatibility, or bandwidth work), update the row here in the
   same commit and add a line to the notes below.

### Notes / history

- 2026-07: budgets introduced (handoff plan Task 0), baselined at v0.15.0.
