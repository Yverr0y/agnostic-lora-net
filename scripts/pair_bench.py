#!/usr/bin/env python3
# pair_bench.py — two-node USB bench harness (BR-11 / BLE-notify follow-up).
#
# Both nodes plugged into USB. WSL: attach each board first (PowerShell, admin):
#   usbipd list
#   usbipd attach --wsl --busid <busid>     (once per board)
#
# Modes:
#   status                      fw / id / name / BLE state + ci/qfull/drop counters per node
#   monitor                     merged timestamped consoles, teed to pair_<ID>.log files.
#                               Run this while reproducing a failure from the webclient —
#                               the v0.17.0 [ble] lines (conn interval, notify-drop) plus
#                               [tun]/[RX] lines show which hop eats the message. Ctrl-C ends.
#   send [--n N] [--size B] [--dir ab|ba|both]
#                               console-send N messages A->B (and/or B->A) over RF and count
#                               [RX] DATA delivered lines on the receiver: pure RF/mesh
#                               delivery + latency, NO browser and NO BLE in the path.
#                               The receiving node must have no BLE client attached (with a
#                               host attached the payload tunnels to it instead of printing).
#   bletest <a|b> --size B --count N
#                               drive the fw's `bletest` on that node while YOUR webclient /
#                               phone is BLE-connected to it: floods seq-numbered frames down
#                               the notify hop with zero RF, then reports the node's own
#                               qfull/drops line. The browser side shows what arrived.
#
# Node A = first port (sorted), B = second; the id/name mapping is printed at startup.
import argparse, glob, queue, re, sys, threading, time

try:
    import serial
except ImportError:
    sys.exit("pyserial missing: pip3 install pyserial")

ID_RE   = re.compile(r'\bnode ([0-9A-Fa-f]{32})\b|\bid=([0-9A-Fa-f]{32})\b')
FW_RE   = re.compile(r'^fw (\S+)')
NAME_RE = re.compile(r'name=(\S*)')
BLE_RE  = re.compile(r'\[ble\] adv=(\d) connected=(\d).*?ci=(\d+) qfull=(\d+) drop=(\d+)')
DELIV_RE= re.compile(r'\[RX\] DATA delivered from ([0-9A-Fa-f]{32}) id=\d+: "([^"]*)')


class Node:
    def __init__(self, dev, label):
        self.dev, self.label = dev, label
        self.s = serial.Serial(dev, 115200, timeout=0.05)
        self.s.dtr = True
        self.s.rts = True
        self.id = None
        self.fw = '?'
        self.name = ''
        self.ble = None                     # (adv, connected, ci, qfull, drop)
        self.q = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        buf = b''
        while True:
            try:
                chunk = self.s.read(256)
            except Exception:
                return
            if not chunk:
                continue
            buf += chunk
            while b'\n' in buf:
                ln, buf = buf.split(b'\n', 1)
                t = ln.decode(errors='replace').rstrip()
                if not t:
                    continue
                m = ID_RE.search(t)
                if m and not self.id:
                    self.id = (m.group(1) or m.group(2)).upper()
                m = FW_RE.match(t)
                if m:
                    self.fw = m.group(1)
                m = NAME_RE.search(t)
                if m and 'name=' in t and t.startswith('node '):
                    self.name = m.group(1)
                m = BLE_RE.search(t)
                if m:
                    self.ble = tuple(int(x) for x in m.groups())
                self.q.put((time.time(), t))

    def cmd(self, line):
        self.s.write((line + '\n').encode())

    def drain(self):
        while not self.q.empty():
            self.q.get_nowait()

    def wait_line(self, pred, timeout):
        """Return (ts, line) for the first queued line matching pred, else None."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                ts, t = self.q.get(timeout=0.1)
            except queue.Empty:
                continue
            if pred(t):
                return ts, t
        return None


def open_nodes():
    devs = sorted(glob.glob('/dev/ttyACM*') + glob.glob('/dev/ttyUSB*'))
    if len(devs) < 2:
        sys.exit(f"need 2 serial devices, found {devs or 'none'} — "
                 "attach both boards (WSL: usbipd attach --wsl --busid <id>)")
    nodes = [Node(devs[0], 'A'), Node(devs[1], 'B')]
    for n in nodes:                          # identify: fw+id+name from `info`
        n.cmd('info')
    deadline = time.time() + 6
    while time.time() < deadline and not all(n.id for n in nodes):
        time.sleep(0.2)
    for n in nodes:
        print(f"  [{n.label}] {n.dev}  id={n.id or '??'}  fw={n.fw}  name={n.name or '-'}")
        if n.fw != '?' and not n.fw.startswith('v0.17') and not n.fw.startswith('0.17'):
            print(f"      ^^ WARNING: not v0.17.0 — the BLE notify fixes are NOT on this node")
    if not all(n.id for n in nodes):
        sys.exit("could not read a node id from both boards (is something else holding the port?)")
    return nodes


def mode_status(nodes, args):
    for n in nodes:
        n.drain()
        n.cmd('ble')
    time.sleep(4)                            # ≥1 heartbeat so the [ble] counter line lands
    for n in nodes:
        if n.ble:
            adv, conn, ci, qfull, drop = n.ble
            ivl = f"{ci*1.25:.2f}ms" if ci else "n/a (no client yet)"
            print(f"[{n.label}] BLE adv={adv} connected={conn} interval={ivl} "
                  f"qfull={qfull} drop={drop}"
                  + ("   <-- drops happening!" if drop else ""))
        else:
            print(f"[{n.label}] no [ble] heartbeat seen — BLE off or old firmware")


def mode_monitor(nodes, args):
    logs = {}
    for n in nodes:
        logs[n.label] = open(f"pair_{n.label}_{(n.id or 'unknown')[:8]}.log", 'a')
    print("-- monitoring both consoles (Ctrl-C to stop) --")
    t0 = time.time()
    try:
        while True:
            idle = True
            for n in nodes:
                try:
                    ts, t = n.q.get_nowait()
                    idle = False
                except queue.Empty:
                    continue
                line = f"[{ts - t0:9.3f}] [{n.label}] {t}"
                print(line)
                logs[n.label].write(line + '\n')
                logs[n.label].flush()
            if idle:
                time.sleep(0.02)
    except KeyboardInterrupt:
        print("\nlogs: " + ", ".join(f.name for f in logs.values()))


def run_direction(tx, rx, n_msgs, size):
    print(f"\n-- {tx.label}->{rx.label}  ({tx.id[:8]}… -> {rx.id[:8]}…)  "
          f"{n_msgs} msgs, {size}B payload --")
    if rx.ble and rx.ble[1]:
        print(f"   NOTE: [{rx.label}] has a BLE client attached — delivered payloads tunnel "
              "to it instead of printing; disconnect it for this test")
    ok, lats = 0, []
    for k in range(n_msgs):
        token = f"pb{k:03d}." + format(int(time.time()) & 0xFFFF, '04x')
        msg = (token + '.' + 'x' * size)[:max(size, len(token))]
        rx.drain()
        t_tx = time.time()
        tx.cmd(f"send {rx.id} {msg}")
        # delivered line carries only the first 63 payload chars — token leads, so it fits
        hit = rx.wait_line(lambda t: 'DATA delivered' in t and token in t, timeout=30)
        if hit:
            dt = hit[0] - t_tx
            lats.append(dt)
            ok += 1
            print(f"   {k+1:3}/{n_msgs}  delivered in {dt:5.2f}s")
        else:
            print(f"   {k+1:3}/{n_msgs}  LOST (30s timeout)")
        time.sleep(1.0)                      # let ACK/console settle between reps
    if lats:
        lats.sort()
        print(f"   => {ok}/{n_msgs} delivered  "
              f"lat min/med/max = {lats[0]:.2f}/{lats[len(lats)//2]:.2f}/{lats[-1]:.2f}s")
    else:
        print(f"   => 0/{n_msgs} delivered — RF/mesh path is broken (not a BLE problem)")


def mode_send(nodes, args):
    a, b = nodes
    if args.dir in ('ab', 'both'):
        run_direction(a, b, args.n, args.size)
    if args.dir in ('ba', 'both'):
        run_direction(b, a, args.n, args.size)


def mode_bletest(nodes, args):
    n = nodes[0] if args.node == 'a' else nodes[1]
    print(f"[{n.label}] bletest {args.size} {args.count} — a BLE client (webclient/phone) "
          f"must be connected+subscribed to THIS node")
    n.drain()
    n.cmd(f"bletest {args.size} {args.count}")
    end = time.time() + 60
    while time.time() < end:
        hit = n.wait_line(lambda t: True, timeout=1)
        if not hit:
            continue
        _, t = hit
        if t.startswith('[ble]') or 'bletest' in t:
            print(f"   {t}")
        if t.startswith('bletest done') or t.startswith('bletest:'):
            return
    print("   (no bletest result within 60s)")


def main():
    p = argparse.ArgumentParser(description="two-node USB bench harness")
    sub = p.add_subparsers(dest='mode', required=True)
    sub.add_parser('status')
    sub.add_parser('monitor')
    ps = sub.add_parser('send')
    ps.add_argument('--n', type=int, default=10)
    ps.add_argument('--size', type=int, default=210,
                    help="payload bytes (default 210 ≈ the failing announce size)")
    ps.add_argument('--dir', choices=['ab', 'ba', 'both'], default='both')
    pb = sub.add_parser('bletest')
    pb.add_argument('node', choices=['a', 'b'])
    pb.add_argument('--size', type=int, default=210)
    pb.add_argument('--count', type=int, default=20)
    args = p.parse_args()

    print("opening boards…")
    nodes = open_nodes()
    {'status': mode_status, 'monitor': mode_monitor,
     'send': mode_send, 'bletest': mode_bletest}[args.mode](nodes, args)


if __name__ == '__main__':
    main()
