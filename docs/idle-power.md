# Idle power reduction (nRF52 light sleep)

Nodes run continuous RX, but the **radio** doing that is the job — the **MCU**
does not need to spin. The SX1262/LR1110 raises DIO1 on RX-done/CAD, so the CPU
can sleep until an interrupt or timer fires. This is the largest battery win
available without changing mesh behaviour, and it is hardening, not a feature.

**Status:** the firmware hook is implemented but **default-off and unverified on
hardware**. It must pass the soak below before the flag is enabled in a build.
This document is the design + the acceptance procedure; the verification is the
substance of the task.

## Why the MCU currently spins

The real work runs in `agn_main_task` (`src/main.cpp`), a FreeRTOS task under
the s140 SoftDevice:

```c
for (;;) { agn_loop_once(); yield(); }
```

`agn_loop_once()` is entirely non-blocking (millis()-scheduled periodic work +
an ISR-backed `radio.poll()`), and `yield()` only drops to an equal/higher
priority task. The FreeRTOS **idle** task — where the Adafruit core parks the
core in `sd_app_evt_wait()` — is *lower* priority and almost never runs, so the
MCU stays awake burning several mA between radio events.

## The change (`AGN_IDLE_SLEEP`, default off)

`agn_idle_wait()` replaces the bare `yield()`:

```c
static inline void agn_idle_wait() {
#if defined(AGN_IDLE_SLEEP) && AGN_IDLE_SLEEP
    if ((bool)Serial) { yield(); return; }   // USB attached -> stay hot
    vTaskDelay(1);                            // ~1 tick: idle task sleeps the MCU
#else
    yield();                                  // default: unchanged behaviour
#endif
}
```

- **`sd_app_evt_wait`, never raw `__WFE`/`__WFI`.** Sleeping is delegated to the
  FreeRTOS idle task / SoftDevice via `vTaskDelay`, which is the SoftDevice-safe
  path. Blocking the main task briefly is what lets the idle task run at all.
- **Wake sources** are unchanged and automatic: the radio's DIO1 IRQ (already
  wired), the RTOS tick, and BLE/SoftDevice events. Polled work sees at most ~1
  tick (~1 ms) of added latency.
- **USB-attached gate** (plan item 3): a powered/attached node stays fully
  responsive and never sleeps — deep savings only matter for battery nodes.
- **Default off** so the shipped firmware's timing and on-air behaviour are
  byte-for-byte unchanged until a build explicitly opts in.

### Latency vs the timing-sensitive paths

The concern is that wake granularity must not break ACK windows. It doesn't:

| deadline | budget | ~1 ms wake latency |
|---|---|---|
| ARQ retransmit (`link_arq`) | `ARQ_TIMEOUT_MS` = 5000 ms | negligible |
| beacon cadence | ~10 s | negligible |
| CAD / ACK turnaround | 10s–100s of ms | within margin |

A radio RX event wakes the CPU immediately (DIO1 IRQ → SoftDevice); the main
task then services it on its next tick, ≤ ~1 ms later. This is the first,
low-risk increment. A later step can go fully tickless (block until the next
scheduled deadline via an ISR task-notification) for even lower wake rates — see
"Follow-ups".

## Acceptance procedure (do this before enabling the flag)

1. **Build two firmwares**: a **control** (default, no flag) and a **sleep**
   (`-DAGN_IDLE_SLEEP=1`). Flash the sleep build to one battery node and the
   control build to an identical node.
2. **Soak**: run a 2-node and a 3-node (multi-hop) bench for **24 h** with
   beacons + periodic SAR transfers, `trace on`, both consoles logged to file.
   Keep the sleep node **unattended** (USB detaches the sleep path).
3. **Analyze** with `scripts/soak_analyze.py`:

   ```sh
   python3 scripts/soak_analyze.py --control control.log --sleep sleep.log
   ```

   It diffs the reliability indicators the firmware already prints — beacon
   reception gaps (missed packets), heartbeat cadence, error lines — and the
   battery-drain slope. **Pass = no beacon-miss regression beyond tolerance and
   no heartbeat stalls; exit status is non-zero on regression** so it can gate
   the run.
4. **Measure idle current**: PPK2 or INA if available; otherwise the
   battery-drain-over-24 h slope from step 3 is the accepted proxy. Record
   before/after per board in this doc's table below and in the README's
   honest-numbers style. Expected order of magnitude: MCU spin (several mA) →
   toward the radio's RX floor (~5 mA class for SX1262 RX + sleeping MCU); total
   node draw should roughly halve, exact numbers per board.

### Measured results (fill in after soak)

| board | idle current before | idle current after | 24 h beacon-miss Δ vs control |
|---|---|---|---|
| RAK4631 | _TBD_ | _TBD_ | _TBD_ |
| XIAO nRF52840 | _TBD_ | _TBD_ | _TBD_ |
| Pro Micro nRF52840 | _TBD_ | _TBD_ | _TBD_ |
| T1000-E | _TBD_ | _TBD_ | _TBD_ |

## Scope / follow-ups

- **nRF52 first** (RAK4631, XIAO, Pro Micro, T1000-E) — this change.
- **ESP32-S3** (Heltec V4, XIAO ESP32-S3): the analogue is `esp_pm` automatic
  light sleep, which interacts with the USB-serial console and Wi-Fi/BT blocks
  differently. Land nRF52 first, then port the same USB-attached-gate structure.
- **Fully tickless** (block until the next scheduled deadline via an
  ISR-posted task notification) is a later optimisation on top of this; it needs
  the radio HAL to expose its DIO1 ISR as a notification source.
- **Out of scope:** deep-sleep leaf/tracker role (duty-cycled RX changes mesh
  semantics — fork territory). This task must not change on-air behaviour at all.
