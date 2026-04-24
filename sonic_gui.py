#!/usr/bin/env python3
"""
Sonic: packet-to-sound with C packet processing.
Runs the C packet_processor binary (libpcap), reads NOTE lines from stdout,
and plays notes via a queue. Simple GUI to start/stop and show status.

Live metrics dashboard: http://localhost:9091
"""
from __future__ import annotations

import collections
import json
import os
import sys
import re
import queue
import random
import threading
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# tkinter is imported only when running GUI (not in --cli), to avoid macOS
# version-check aborts from Tcl/Tk in some environments.
MAX_QUEUE = 256
MAX_NOTES_PER_SEC = 120
NOTE_DURATION_MIN_MS = 1400
NOTE_DURATION_MAX_MS = 5500
NOTE_JITTER_MS       = 600
OVERLAP_MIN, OVERLAP_MAX = 1, 1
NOTE_PATTERN = re.compile(r"^NOTE\s+(?:(tcp|udp)\s+)?([\d.]+)\s+(\d+)\s*$")

DASHBOARD_PORT = 9091   # http://localhost:9091  →  live graphs


# ── Metrics store + rolling history ──────────────────────────────────────────

class MetricsStore:
    """Thread-safe counters + 90-second rolling history for the dashboard."""
    MAXLEN = 90

    def __init__(self):
        self._lock        = threading.Lock()
        self.packets_tcp  = 0
        self.packets_udp  = 0
        self.notes_played = 0
        self.queue_size   = 0
        self._hist_tcp    = collections.deque(maxlen=self.MAXLEN)
        self._hist_udp    = collections.deque(maxlen=self.MAXLEN)
        self._hist_notes  = collections.deque(maxlen=self.MAXLEN)
        self._hist_queue  = collections.deque(maxlen=self.MAXLEN)
        self._hist_labels = collections.deque(maxlen=self.MAXLEN)
        self._prev_tcp    = 0
        self._prev_udp    = 0
        self._prev_notes  = 0

    def inc_packet(self, protocol: str):
        with self._lock:
            if protocol == "tcp":
                self.packets_tcp += 1
            else:
                self.packets_udp += 1

    def inc_note(self):
        with self._lock:
            self.notes_played += 1

    def set_queue(self, n: int):
        with self._lock:
            self.queue_size = n

    def tick(self):
        """Record one sample (call every second from a daemon thread)."""
        with self._lock:
            self._hist_labels.append(time.strftime("%H:%M:%S"))
            self._hist_tcp.append(self.packets_tcp   - self._prev_tcp)
            self._hist_udp.append(self.packets_udp   - self._prev_udp)
            self._hist_notes.append(self.notes_played - self._prev_notes)
            self._hist_queue.append(self.queue_size)
            self._prev_tcp   = self.packets_tcp
            self._prev_udp   = self.packets_udp
            self._prev_notes = self.notes_played

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "labels": list(self._hist_labels),
                "tcp":    list(self._hist_tcp),
                "udp":    list(self._hist_udp),
                "notes":  list(self._hist_notes),
                "queue":  list(self._hist_queue),
                "totals": {
                    "tcp":   self.packets_tcp,
                    "udp":   self.packets_udp,
                    "notes": self.notes_played,
                    "queue": self.queue_size,
                },
            }

    def prometheus_text(self) -> str:
        s = self.snapshot()
        return (
            "# HELP sonic_packets_total Packets captured\n"
            "# TYPE sonic_packets_total counter\n"
            f'sonic_packets_total{{protocol="tcp"}} {s["totals"]["tcp"]}\n'
            f'sonic_packets_total{{protocol="udp"}} {s["totals"]["udp"]}\n'
            "# HELP sonic_notes_total Notes played\n"
            "# TYPE sonic_notes_total counter\n"
            f'sonic_notes_total {s["totals"]["notes"]}\n'
            "# HELP sonic_queue_size Note queue depth\n"
            "# TYPE sonic_queue_size gauge\n"
            f'sonic_queue_size {s["totals"]["queue"]}\n'
        )


# ── Live dashboard HTML ───────────────────────────────────────────────────────

DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sonic — Live Metrics</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0b0b1a;color:#d8d8f0;font-family:'SF Mono',Consolas,monospace;padding:28px 32px}
  header{display:flex;align-items:center;gap:14px;margin-bottom:28px}
  h1{font-size:1.35rem;letter-spacing:3px;color:#7eb8f7;text-transform:uppercase}
  .dot{width:11px;height:11px;background:#3dff8f;border-radius:50%;
       animation:pulse 1.4s ease-in-out infinite;flex-shrink:0}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.65)}}
  .sub{font-size:.72rem;color:#555;margin-left:auto;letter-spacing:1px}
  .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
  .card{background:#11112a;border:1px solid #22224a;border-radius:14px;padding:18px 20px}
  .card-label{font-size:.68rem;color:#666;letter-spacing:1.5px;text-transform:uppercase}
  .card-value{font-size:2.1rem;font-weight:700;margin-top:6px;font-variant-numeric:tabular-nums}
  .c-tcp   .card-value{color:#5b9cf6}
  .c-udp   .card-value{color:#f6955b}
  .c-notes .card-value{color:#4df6a0}
  .c-queue .card-value{color:#f6e25b}
  .charts{display:grid;gap:20px}
  .chart-box{background:#11112a;border:1px solid #22224a;border-radius:14px;padding:22px 24px}
  .chart-box h2{font-size:.7rem;letter-spacing:1.5px;color:#666;
                text-transform:uppercase;margin-bottom:16px}
  canvas{max-height:190px}
</style>
</head>
<body>
<header>
  <div class="dot"></div>
  <h1>⬡ Sonic &mdash; Live Network Metrics</h1>
  <span class="sub" id="ts">--:--:--</span>
</header>

<div class="cards">
  <div class="card c-tcp">
    <div class="card-label">TCP Packets</div>
    <div class="card-value" id="v-tcp">0</div>
  </div>
  <div class="card c-udp">
    <div class="card-label">UDP Packets</div>
    <div class="card-value" id="v-udp">0</div>
  </div>
  <div class="card c-notes">
    <div class="card-label">Notes Played</div>
    <div class="card-value" id="v-notes">0</div>
  </div>
  <div class="card c-queue">
    <div class="card-label">Queue Depth</div>
    <div class="card-value" id="v-queue">0</div>
  </div>
</div>

<div class="charts">
  <div class="chart-box">
    <h2>Packets / second</h2>
    <canvas id="ch-pkt"></canvas>
  </div>
  <div class="chart-box">
    <h2>Notes / second &amp; Queue depth</h2>
    <canvas id="ch-notes"></canvas>
  </div>
</div>

<script>
const defaults = {
  animation: false, responsive: true, maintainAspectRatio: true,
  interaction: { mode: 'index', intersect: false },
  scales: {
    x: { ticks: { color: '#555', maxTicksLimit: 10 }, grid: { color: '#1a1a30' } },
    y: { ticks: { color: '#555' }, grid: { color: '#1a1a30' }, beginAtZero: true }
  },
  plugins: { legend: { labels: { color: '#999', boxWidth: 12, padding: 16 } } }
};
const ds = (label, color, fill=true, dash=[]) => ({
  label, data: [],
  borderColor: color,
  backgroundColor: fill ? color + '22' : 'transparent',
  borderWidth: 2, pointRadius: 0, tension: 0.38, fill,
  borderDash: dash
});
const mkChart = (id, datasets) => new Chart(
  document.getElementById(id),
  { type: 'line', data: { labels: [], datasets }, options: { ...defaults } }
);

const chPkt   = mkChart('ch-pkt',   [ds('TCP',    '#5b9cf6'), ds('UDP', '#f6955b')]);
const chNotes = mkChart('ch-notes', [ds('Notes/s','#4df6a0'), ds('Queue','#f6e25b',false,[4,3])]);

function fmt(n){ return Number(n).toLocaleString(); }

function apply(data) {
  document.getElementById('v-tcp').textContent   = fmt(data.totals.tcp);
  document.getElementById('v-udp').textContent   = fmt(data.totals.udp);
  document.getElementById('v-notes').textContent = fmt(data.totals.notes);
  document.getElementById('v-queue').textContent = fmt(data.totals.queue);
  document.getElementById('ts').textContent      = new Date().toLocaleTimeString();

  chPkt.data.labels = chNotes.data.labels = data.labels;
  chPkt.data.datasets[0].data   = data.tcp;
  chPkt.data.datasets[1].data   = data.udp;
  chNotes.data.datasets[0].data = data.notes;
  chNotes.data.datasets[1].data = data.queue;
  chPkt.update('none');
  chNotes.update('none');
}

async function poll() {
  try {
    const r = await fetch('/data');
    if (r.ok) apply(await r.json());
  } catch(_) {}
  setTimeout(poll, 1500);
}
poll();
</script>
</body>
</html>
"""


# ── Dashboard HTTP server ─────────────────────────────────────────────────────

def _start_dashboard(port: int, store: MetricsStore) -> None:
    """Start HTTP server + 1-second sampler in daemon threads."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # suppress access logs

        def _send(self, code: int, ctype: str, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8",
                           DASHBOARD_HTML.encode())
            elif self.path == "/data":
                self._send(200, "application/json",
                           json.dumps(store.snapshot()).encode())
            elif self.path == "/metrics":
                self._send(200, "text/plain; version=0.0.4; charset=utf-8",
                           store.prometheus_text().encode())
            else:
                self._send(404, "text/plain", b"Not found")

    def sampler():
        while True:
            time.sleep(1)
            store.tick()

    threading.Thread(target=sampler, daemon=True).start()

    try:
        srv = HTTPServer(("", port), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    except OSError as e:
        print(f"Dashboard: could not bind to port {port}: {e}", file=sys.stderr)


# ── Audio helpers ─────────────────────────────────────────────────────────────

def get_audio_helper_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "sonic_audio_helper.py")


def player_worker(note_queue: queue.Queue, stop_event: threading.Event,
                  log_callback=None, metrics_store: MetricsStore | None = None,
                  audio_helper_path: str = None):
    if not audio_helper_path or not os.path.isfile(audio_helper_path):
        if log_callback:
            log_callback("Audio: sonic_audio_helper.py not found.")
        return
    try:
        proc = subprocess.Popen(
            [sys.executable, audio_helper_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except Exception as e:
        if log_callback:
            log_callback(f"Audio: failed to start helper: {e}")
        return
    log_once = [True]

    try:
        while not stop_event.is_set():
            try:
                item = note_queue.get(timeout=0.2)
                if item is None:
                    break
                freq, duration_ms = item[0], item[1]
                overlap = item[2] if len(item) > 2 else random.randint(OVERLAP_MIN, OVERLAP_MAX)
                if proc.poll() is not None:
                    if log_callback and log_once[0]:
                        log_once[0] = False
                        log_callback("Audio: helper process exited. Sound disabled.")
                    break
                scaled = max(
                    NOTE_DURATION_MIN_MS,
                    min(NOTE_DURATION_MAX_MS, int(duration_ms * 1.4) + random.randint(0, 900)),
                )
                played_ms = max(
                    NOTE_DURATION_MIN_MS,
                    min(NOTE_DURATION_MAX_MS,
                        scaled + random.randint(-NOTE_JITTER_MS, NOTE_JITTER_MS)),
                )
                proc.stdin.write(f"{freq} {played_ms} {overlap}\n")
                proc.stdin.flush()
                if metrics_store is not None:
                    metrics_store.inc_note()
            except queue.Empty:
                continue
            except BrokenPipeError:
                if log_callback and log_once[0]:
                    log_once[0] = False
                    log_callback("Audio: helper crashed. Sound disabled.")
                break
    except Exception as e:
        if log_callback:
            log_callback(f"Playback error: {e}")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def find_interfaces():
    try:
        out = subprocess.run(
            ["sh", "-c",
             "ifconfig -l 2>/dev/null || ip -o link show | awk -F': ' '{print $2}' 2>/dev/null"],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0 and out.stdout.strip():
            return [s.strip() for s in out.stdout.strip().split() if s.strip()]
    except Exception:
        pass
    return []


def _needs_sudo(path: str) -> bool:
    from sonic_priv import bpf_accessible, _has_setuid_root
    if bpf_accessible():
        return False
    return not _has_setuid_root(path)


def _user_in_bpf_group() -> bool:
    try:
        import grp, pwd
        username = pwd.getpwuid(os.getuid()).pw_name
        return username in grp.getgrnam("access_bpf").gr_mem
    except Exception:
        return False


def _build_cmd(binary_path: str, interface: str) -> list:
    from sonic_priv import bpf_accessible, _has_setuid_root
    args = [binary_path]
    if interface and interface != "default":
        args.append(interface)
    if bpf_accessible() or _has_setuid_root(binary_path):
        return args
    if _user_in_bpf_group():
        shell = " ".join(f"'{a}'" for a in args)
        return ["sg", "access_bpf", "-c", shell]
    return ["sudo"] + args


def run_capture(binary_path: str, interface: str, note_queue: queue.Queue,
                log_callback, stop_event: threading.Event,
                metrics_store: MetricsStore | None = None):
    cmd = _build_cmd(binary_path, interface)
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        def read_stderr():
            for line in proc.stderr:
                if stop_event.is_set():
                    break
                log_callback(line.strip())

        threading.Thread(target=read_stderr, daemon=True).start()

        notes_received = 0
        enqueue_times  = []
        for line in proc.stdout:
            if stop_event.is_set():
                break
            m = NOTE_PATTERN.match(line.strip())
            if m:
                protocol    = (m.group(1) or "unknown").lower()
                freq        = float(m.group(2))
                duration_ms = int(m.group(3))
                notes_received += 1
                if metrics_store is not None:
                    metrics_store.inc_packet(protocol)
                    metrics_store.set_queue(note_queue.qsize())
                if notes_received <= 3 or notes_received % 50 == 0:
                    log_callback(f"Note #{notes_received}: {freq:.0f} Hz ({protocol})")
                now = time.monotonic()
                enqueue_times = [t for t in enqueue_times if now - t < 1.0]
                if len(enqueue_times) < MAX_NOTES_PER_SEC and note_queue.qsize() < MAX_QUEUE:
                    note_queue.put((freq, duration_ms, random.randint(OVERLAP_MIN, OVERLAP_MAX)))
                    enqueue_times.append(now)
        proc.wait()
    except FileNotFoundError:
        log_callback("Error: packet_processor binary not found. Run: make")
    except PermissionError:
        log_callback("Error: run as user. You may be prompted for password.")
    except Exception as e:
        log_callback(f"Error: {e}")


def run_cli(interface: str = "default"):
    """Terminal mode — no GUI, no tkinter."""
    binary_dir  = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(binary_dir, "packet_processor")
    if not os.path.isfile(binary_path):
        print("Error: packet_processor not found. Run: make", file=sys.stderr)
        return

    note_queue    = queue.Queue()
    stop_event    = threading.Event()
    metrics_store = MetricsStore()

    _start_dashboard(DASHBOARD_PORT, metrics_store)
    print(f"Dashboard: http://localhost:{DASHBOARD_PORT}")

    def log_cb(msg):
        print(msg)

    helper_path = get_audio_helper_path()
    threading.Thread(
        target=player_worker,
        args=(note_queue, stop_event, log_cb, metrics_store, helper_path),
        daemon=True,
    ).start()
    capture_thread = threading.Thread(
        target=run_capture,
        args=(binary_path, interface, note_queue, log_cb, stop_event),
        kwargs={"metrics_store": metrics_store},
        daemon=True,
    )
    capture_thread.start()
    log_cb(f"Sonic CLI: capture started on {interface}. Ctrl+C to stop.")
    try:
        while capture_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    stop_event.set()
    note_queue.put(None)
    capture_thread.join(timeout=3)
    log_cb("Stopped.")


# ── GUI ───────────────────────────────────────────────────────────────────────

class SonicApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Sonic — Packet to Sound")
        self.root.geometry("420x320")
        self.root.resizable(True, True)

        self.binary_dir  = os.path.dirname(os.path.abspath(__file__))
        self.binary_path = os.path.join(self.binary_dir, "packet_processor")
        self.note_queue   = queue.Queue()
        self.stop_event   = threading.Event()
        self.capture_thread = None
        self.player_thread  = None

        self.metrics_store = MetricsStore()
        _start_dashboard(DASHBOARD_PORT, self.metrics_store)

        # Controls
        frame = ttk.Frame(root, padding=10)
        frame.pack(fill=tk.X)

        ttk.Label(frame, text="Interface:").pack(side=tk.LEFT, padx=(0, 4))
        self.iface_var = tk.StringVar(value="default")
        ifaces = ["default"] + find_interfaces()
        self.iface_combo = ttk.Combobox(frame, textvariable=self.iface_var,
                                        values=ifaces, width=14)
        self.iface_combo.pack(side=tk.LEFT, padx=(0, 8))

        self.start_btn = ttk.Button(frame, text="Start", command=self.start)
        self.start_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(frame, text="Stop", command=self.stop,
                                   state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(frame, text="Test sound",
                   command=self._test_sound).pack(side=tk.LEFT, padx=4)

        # Log
        ttk.Label(root, text="Status / log:").pack(anchor=tk.W, padx=10, pady=(4, 0))
        self.log = scrolledtext.ScrolledText(root, height=10,
                                             state=tk.DISABLED, wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        self._log_audio_device()
        self.log_msg(f"Live dashboard → http://localhost:{DASHBOARD_PORT}")
        self.log_msg("Ready. Click 'Test sound' to verify audio.")
        if _needs_sudo(self.binary_path):
            self.log_msg("ℹ First click of Start shows a one-time macOS password dialog.")
        else:
            self.log_msg("✓ BPF access ready — click Start to begin.")

    def log_msg(self, msg: str):
        self.log.config(state=tk.NORMAL)
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    def _log_audio_device(self):
        helper = get_audio_helper_path()
        if not os.path.isfile(helper):
            self.log_msg("Audio: sonic_audio_helper.py not found.")
            return
        try:
            r = subprocess.run(
                [sys.executable, helper, "--check"],
                capture_output=True, text=True, timeout=5,
                cwd=os.path.dirname(helper),
            )
            if r.returncode == 0 and r.stdout.strip():
                self.log_msg(f"Audio out: {r.stdout.strip()}")
            else:
                self.log_msg("Audio: helper check failed. Try Test sound.")
        except subprocess.TimeoutExpired:
            self.log_msg("Audio: helper check timed out.")
        except Exception as e:
            self.log_msg(f"Audio device check failed: {e}")

    def _test_sound(self):
        def do_play():
            helper = get_audio_helper_path()
            if not os.path.isfile(helper):
                self.root.after(0, lambda: self.log_msg(
                    "Test sound: sonic_audio_helper.py not found."))
                return
            try:
                proc = subprocess.Popen(
                    [sys.executable, helper],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, text=True,
                    cwd=os.path.dirname(helper),
                )
                with proc:
                    for _ in range(3):
                        proc.stdin.write(f"440 {random.randint(350, 600)}\n")
                        proc.stdin.flush()
                    proc.stdin.close()
                proc.wait(timeout=5)
                if proc.returncode == 0:
                    self.root.after(0, lambda: self.log_msg("Test sound: 3 notes played."))
                else:
                    raise RuntimeError(f"Helper exited {proc.returncode}")
            except Exception as e:
                self.root.after(0, lambda: self.log_msg(f"Test sound error: {e}"))
                try:
                    if sys.platform == "darwin":
                        subprocess.run(["afplay", "/System/Library/Sounds/Tink.aiff"],
                                       capture_output=True, timeout=2)
                        self.root.after(0, lambda: self.log_msg(
                            "System sound (Tink) played as fallback."))
                except Exception:
                    pass
                self.root.after(0, lambda: messagebox.showerror(
                    "Audio error",
                    "Audio helper failed.\n\nCapture will still work; "
                    "notes will be logged.",
                ))

        threading.Thread(target=do_play, daemon=True).start()

    def start(self):
        if not os.path.isfile(self.binary_path):
            messagebox.showerror("Error", "packet_processor not found. Run: make")
            return

        # One-time BPF access setup (access_bpf group + chmod /dev/bpf*)
        if _needs_sudo(self.binary_path):
            self.log_msg("⚙ First-time setup: requesting access to /dev/bpf*…")
            from sonic_priv import ensure_bpf_access
            ok = ensure_bpf_access(parent_window=self.root)
            if not ok:
                self.log_msg("✗ Setup cancelled. Cannot capture without BPF access.")
                return
            self.log_msg("✓ BPF access granted — no more prompts needed.")

        self.stop_event.clear()
        self.note_queue = queue.Queue()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_msg("Starting capture…")

        def log_cb(msg):
            self.root.after(0, lambda: self.log_msg(msg))

        def run():
            run_capture(
                self.binary_path,
                self.iface_var.get().strip(),
                self.note_queue,
                log_cb,
                self.stop_event,
                metrics_store=self.metrics_store,
            )
            self.root.after(0, self._capture_finished)

        self.capture_thread = threading.Thread(target=run, daemon=True)
        self.player_thread  = threading.Thread(
            target=player_worker,
            args=(self.note_queue, self.stop_event, log_cb,
                  self.metrics_store, get_audio_helper_path()),
            daemon=True,
        )
        self.capture_thread.start()
        self.player_thread.start()

    def _capture_finished(self):
        self.stop_event.set()
        self.note_queue.put(None)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_msg("Stopped.")

    def stop(self):
        self.stop_event.set()
        self.note_queue.put(None)

    def on_closing(self):
        self.stop_event.set()
        self.note_queue.put(None)
        self.root.destroy()


def main():
    root = tk.Tk()
    app  = SonicApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        argv      = [a for a in sys.argv[1:] if a != "--cli"]
        interface = argv[0].strip() if argv else "default"
        run_cli(interface)
    else:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox
        main()
