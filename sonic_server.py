#!/usr/bin/env python3
"""
Sonic Web Server — packet-to-sound, browser-based UI.

Run:  python sonic_server.py [interface] [--port 8080]
Then: open http://localhost:8080

Audio is synthesized entirely in the browser via Web Audio API —
no sounddevice, no local audio setup needed.
"""
from __future__ import annotations

import collections
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time

from flask import Flask, Response, jsonify
from flask_socketio import SocketIO, emit

from sonic_priv import bpf_accessible, ensure_bpf_access, _has_setuid_root as _has_setuid

# ── Constants ──────────────────────────────────────────────────────────────────

MAX_NOTES_PER_SEC    = 120
NOTE_DURATION_MIN_MS = 1400
NOTE_DURATION_MAX_MS = 5500
NOTE_JITTER_MS       = 600
NOTE_PATTERN = re.compile(r"^NOTE\s+(?:(tcp|udp)\s+)?([\d.]+)\s+(\d+)\s*$")
WEB_PORT = 8080

# ── Metrics store ──────────────────────────────────────────────────────────────

class MetricsStore:
    """Thread-safe counters + 90-second rolling history."""
    MAXLEN = 90

    def __init__(self):
        self._lock        = threading.Lock()
        self.packets_tcp  = 0
        self.packets_udp  = 0
        self.notes_played = 0
        self._hist_tcp    = collections.deque(maxlen=self.MAXLEN)
        self._hist_udp    = collections.deque(maxlen=self.MAXLEN)
        self._hist_notes  = collections.deque(maxlen=self.MAXLEN)
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

    def tick(self):
        with self._lock:
            self._hist_labels.append(time.strftime("%H:%M:%S"))
            self._hist_tcp.append(self.packets_tcp   - self._prev_tcp)
            self._hist_udp.append(self.packets_udp   - self._prev_udp)
            self._hist_notes.append(self.notes_played - self._prev_notes)
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
                "totals": {
                    "tcp":   self.packets_tcp,
                    "udp":   self.packets_udp,
                    "notes": self.notes_played,
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
        )


# ── Flask + SocketIO ───────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = "sonic-capstone-2026"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

_metrics                          = MetricsStore()
_stop_event                       = threading.Event()
_capture_thread: threading.Thread | None = None
_proc:          subprocess.Popen  | None = None   # tracked for clean kill


# ── Helpers ────────────────────────────────────────────────────────────────────

def _binary_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "packet_processor")


# Internal/virtual interfaces to hide from the selector
_IFACE_SKIP = re.compile(
    r'^(lo\d*|gif\d*|stf\d*|awdl\d*|llw\d*|utun\d*|anpi\d*|bridge\d*|ap\d+|p2p\d*)$'
)

def _find_interfaces() -> list[str]:
    raw: list[str] = []
    # macOS
    try:
        out = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=3)
        if out.returncode == 0 and out.stdout.strip():
            raw = out.stdout.strip().split()
    except Exception:
        pass
    # Linux fallback
    if not raw:
        try:
            out = subprocess.run(["ip", "-o", "link", "show"],
                                 capture_output=True, text=True, timeout=3)
            if out.returncode == 0:
                raw = re.findall(r'^\d+:\s+(\S+):', out.stdout, re.MULTILINE)
        except Exception:
            pass
    # Keep only physical / useful interfaces; put en0 first if present
    filtered = [i for i in raw if i and not _IFACE_SKIP.match(i)]
    if "en0" in filtered:
        filtered = ["en0"] + [i for i in filtered if i != "en0"]
    return filtered


def _kill_proc() -> None:
    """Terminate the capture subprocess and its entire process group."""
    global _proc
    if _proc is None or _proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(_proc.pid), signal.SIGTERM)
    except Exception:
        try:
            _proc.terminate()
        except Exception:
            pass


def _needs_sudo(binary: str) -> bool:
    """Return False if we can capture without root (BPF accessible or setuid set)."""
    if bpf_accessible():
        return False
    return not _has_setuid(binary)


def _user_in_bpf_group() -> bool:
    """Check directory-service group membership (works before re-login)."""
    try:
        import grp, pwd
        username = pwd.getpwuid(os.getuid()).pw_name
        return username in grp.getgrnam("access_bpf").gr_mem
    except Exception:
        return False


def _build_cmd(binary: str, interface: str) -> list[str]:
    """
    Build the subprocess command for packet_processor.

    Priority:
      1. BPF accessible in current process → run directly
      2. User is in access_bpf group (just added this session) → use 'sg access_bpf'
         so the child process inherits the group without needing a re-login
      3. Setuid bit on binary → run directly
      4. Fallback → sudo
    """
    args = [binary]
    if interface and interface != "default":
        args.append(interface)

    if bpf_accessible() or _has_setuid(binary):
        return args                                      # run directly

    if _user_in_bpf_group():
        # sg spawns the command with access_bpf as supplementary group
        shell = " ".join(f"'{a}'" for a in args)
        return ["sg", "access_bpf", "-c", shell]

    return ["sudo"] + args                               # last resort


def _run_capture(binary: str, interface: str) -> None:
    """Run packet_processor and broadcast NOTE events via SocketIO."""
    global _proc

    cmd = _build_cmd(binary, interface)

    def log(msg: str):
        socketio.emit("log", {"msg": msg})

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid,   # own process group → clean group kill on stop
        )
        _proc = proc

        def _stderr():
            for line in proc.stderr:
                if _stop_event.is_set():
                    break
                log(line.strip())

        threading.Thread(target=_stderr, daemon=True).start()

        n_received  = 0
        rate_window: list[float] = []

        for raw in proc.stdout:
            if _stop_event.is_set():
                break
            m = NOTE_PATTERN.match(raw.strip())
            if not m:
                continue
            protocol    = (m.group(1) or "unknown").lower()
            freq        = float(m.group(2))
            duration_ms = int(m.group(3))
            n_received += 1

            _metrics.inc_packet(protocol)

            now = time.monotonic()
            rate_window = [t for t in rate_window if now - t < 1.0]
            if len(rate_window) >= MAX_NOTES_PER_SEC:
                continue

            scaled = max(
                NOTE_DURATION_MIN_MS,
                min(NOTE_DURATION_MAX_MS, int(duration_ms * 1.4) + random.randint(0, 900)),
            )
            played_ms = max(
                NOTE_DURATION_MIN_MS,
                min(NOTE_DURATION_MAX_MS,
                    scaled + random.randint(-NOTE_JITTER_MS, NOTE_JITTER_MS)),
            )
            _metrics.inc_note()
            socketio.emit("note", {
                "freq":         freq,
                "duration":     played_ms,
                "raw_duration": duration_ms,
                "protocol":     protocol,
            })
            rate_window.append(now)

            if n_received <= 3 or n_received % 50 == 0:
                log(f"Note #{n_received}: {freq:.0f} Hz  ({protocol})")

        proc.wait()

    except FileNotFoundError:
        log("Error: packet_processor binary not found — run:  make")
    except PermissionError:
        log("Error: permission denied. sudo password may be needed in the terminal.")
    except Exception as exc:
        log(f"Capture error: {exc}")
    finally:
        _proc = None
        socketio.emit("status", {"running": False})
        log("Capture stopped.")


def _start_sampler() -> None:
    def _loop():
        while True:
            time.sleep(1)
            _metrics.tick()
    threading.Thread(target=_loop, daemon=True).start()


# ── HTTP routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return SONIC_HTML

@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(["default"] + _find_interfaces())

@app.route("/api/metrics")
def api_metrics():
    return jsonify(_metrics.snapshot())

@app.route("/metrics")
def prometheus():
    return Response(_metrics.prometheus_text(),
                    mimetype="text/plain; version=0.0.4; charset=utf-8")


# ── SocketIO events ────────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    running = _capture_thread is not None and _capture_thread.is_alive()
    emit("status", {"running": running})
    bp = _binary_path()
    if os.path.isfile(bp) and _needs_sudo(bp):
        emit("log", {"msg": (
            "⚙ First-time setup needed — a macOS password dialog will appear "
            "when you click Start (one time only)."
        )})
    else:
        emit("log", {"msg": "✓ Ready — click Start to capture."})

@socketio.on("start")
def on_start(data):
    global _capture_thread, _stop_event

    if _capture_thread and _capture_thread.is_alive():
        emit("log", {"msg": "Already running."})
        return

    bp = _binary_path()
    if not os.path.isfile(bp):
        emit("log", {"msg": "Error: packet_processor not found — run:  make"})
        return

    # One-time setup: grant BPF device access (dseditgroup + chmod /dev/bpf*)
    # Uses the same mechanism as Wireshark — no chown on the binary needed.
    if not bpf_accessible() and not _has_setuid(bp):
        emit("log", {"msg": "⚙ First-time setup — a macOS password dialog will appear…"})
        ok = ensure_bpf_access()
        if not ok:
            emit("log", {"msg": "✗ Setup cancelled. Use the launcher script for terminal-based sudo setup."})
            return
        emit("log", {"msg": "✓ BPF access granted — no more prompts needed."})

    interface   = (data or {}).get("interface", "default")
    _stop_event = threading.Event()
    _capture_thread = threading.Thread(
        target=_run_capture, args=(bp, interface), daemon=True,
    )
    _capture_thread.start()
    socketio.emit("status", {"running": True})
    sudo_note = " (sudo password may be needed in this terminal)" if _needs_sudo(bp) else ""
    emit("log", {"msg": f"Capture started on '{interface}'.{sudo_note}"})

@socketio.on("stop")
def on_stop():
    _stop_event.set()
    _kill_proc()
    emit("log", {"msg": "Stopping…"})


# ── Embedded Web UI ────────────────────────────────────────────────────────────

SONIC_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sonic — Network to Music</title>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07070f;--surface:#0e0e1e;--border:#1e1e3a;
  --tcp:#5b9cf6;--udp:#f6955b;--note:#4df6a0;
  --text:#c8c8e8;--muted:#44445a;--accent:#7b6ef6;
}
html,body{height:100%;background:var(--bg);color:var(--text);
  font-family:'SF Mono',ui-monospace,Consolas,monospace;font-size:13px}
body{display:grid;grid-template-rows:auto auto 1fr auto;min-height:100vh}

/* ── Header ── */
header{padding:16px 28px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:14px;background:var(--surface)}
.logo{font-size:1.4rem;font-weight:700;letter-spacing:6px;color:#fff;
  text-transform:uppercase;text-shadow:0 0 18px var(--accent)}
.pulse-dot{width:10px;height:10px;border-radius:50%;background:#3dff8f;flex-shrink:0;
  box-shadow:0 0 8px #3dff8f;transition:background .3s,box-shadow .3s}
.pulse-dot.active{animation:pulse 1.3s ease-in-out infinite}
.pulse-dot.idle{background:#2a2a3a;box-shadow:none}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.6)}}
.status-badge{font-size:.65rem;letter-spacing:2px;padding:3px 10px;border-radius:20px;
  border:1px solid var(--border);color:var(--muted);text-transform:uppercase;margin-left:auto}
.status-badge.running{border-color:#3dff8f55;color:#3dff8f}

/* ── Tab bar ── */
.tab-bar{display:flex;gap:2px;padding:0 28px;background:var(--surface);
  border-bottom:1px solid var(--border)}
.tab-btn{padding:9px 20px;font-family:inherit;font-size:.72rem;letter-spacing:1.5px;
  text-transform:uppercase;background:transparent;color:var(--muted);border:none;
  border-bottom:2px solid transparent;cursor:pointer;transition:color .2s,border-color .2s;outline:none}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent)}

/* ── Panels ── */
.panel{padding:20px 28px;display:flex;flex-direction:column;gap:16px;overflow-y:auto}
.panel.hidden{display:none!important}

/* ── Controls ── */
.controls{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
select,button{font-family:inherit;font-size:.8rem;border-radius:8px;border:1px solid var(--border);
  background:var(--surface);color:var(--text);padding:7px 14px;cursor:pointer;
  transition:border-color .2s,background .2s,box-shadow .2s;outline:none}
select:hover,button:hover{border-color:var(--accent)}
select:focus{border-color:var(--accent);box-shadow:0 0 0 2px #7b6ef622}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent);font-weight:600}
button.primary:hover{background:#6a5ee0;box-shadow:0 0 12px #7b6ef644}
button.danger{background:#3a1a1a;color:#f67b7b;border-color:#5a2222}
button.danger:hover{background:#4a2020;box-shadow:0 0 12px #f67b7b22}
button:disabled{opacity:.4;cursor:not-allowed}
label{font-size:.72rem;color:var(--muted);letter-spacing:1px;text-transform:uppercase}
.audio-notice{display:flex;align-items:center;gap:8px;font-size:.72rem;color:var(--muted);
  padding:7px 13px;border:1px solid var(--border);border-radius:8px}
#audio-status{color:var(--note)}
#btn-raw{border-color:#4df6a055;color:var(--note)}
#btn-raw.raw-mode{background:#f6e25b22;border-color:var(--queue);color:var(--queue)}

/* ── Live viz canvas ── */
#viz{width:100%;height:150px;border-radius:12px;border:1px solid var(--border);
  background:#070710;display:block}

/* ── Stats cards ── */
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 18px}
.card-label{font-size:.6rem;letter-spacing:1.8px;color:var(--muted);text-transform:uppercase}
.card-value{font-size:1.85rem;font-weight:700;margin-top:5px;font-variant-numeric:tabular-nums}
.card-delta{font-size:.65rem;color:var(--muted);margin-top:2px}
.c-tcp  .card-value{color:var(--tcp)}
.c-udp  .card-value{color:var(--udp)}
.c-notes .card-value{color:var(--note)}

/* ── Charts ── */
.charts{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.chart-box{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px}
.chart-box h2{font-size:.6rem;letter-spacing:1.8px;color:var(--muted);
  text-transform:uppercase;margin-bottom:12px}
canvas.chart{max-height:140px}

/* ── Log ── */
.log-box{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:13px 16px}
.log-box h2{font-size:.6rem;letter-spacing:1.8px;color:var(--muted);
  text-transform:uppercase;margin-bottom:8px}
#log{height:100px;overflow-y:auto;font-size:.72rem;line-height:1.65;color:#555;
  scrollbar-width:thin;scrollbar-color:#1a1a2e transparent}
#log .entry{padding:1px 0;border-bottom:1px solid #0c0c18}
#log .entry:last-child{color:var(--text)}

/* ── Piano roll ── */
.piano-wrap{display:flex;border:1px solid var(--border);border-radius:12px;
  overflow:hidden;background:#06060e;flex:1;min-height:380px}
.piano-keys{width:52px;flex-shrink:0;background:#0a0a18;border-right:1px solid var(--border);
  position:relative;overflow:hidden}
#piano-canvas{flex:1;display:block;cursor:crosshair}
.piano-legend{display:flex;gap:18px;align-items:center;font-size:.68rem;color:var(--muted)}
.legend-dot{width:10px;height:10px;border-radius:3px;flex-shrink:0}

/* ── Packet table ── */
.pkt-wrap{flex:1;overflow-y:auto;border:1px solid var(--border);border-radius:12px;
  background:#06060e;min-height:360px;max-height:calc(100vh - 200px)}
.pkt-table{width:100%;border-collapse:collapse;font-size:.74rem;font-variant-numeric:tabular-nums}
.pkt-table thead{position:sticky;top:0;background:#0d0d1e;z-index:2}
.pkt-table th{padding:8px 12px;text-align:left;font-size:.6rem;letter-spacing:1.5px;
  text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);
  white-space:nowrap}
.pkt-table td{padding:4px 12px;border-bottom:1px solid #0b0b18;color:#aaa;white-space:nowrap}
.pkt-table tr.tcp td{border-left:2px solid #5b9cf6;background:#5b9cf608}
.pkt-table tr.udp td{border-left:2px solid #f6955b;background:#f6955b08}
.pkt-table tr.tcp td:nth-child(3){color:var(--tcp);font-weight:600}
.pkt-table tr.udp td:nth-child(3){color:var(--udp);font-weight:600}
.pkt-table td:nth-child(5){color:var(--note)}
.pkt-table tbody tr:last-child td{color:var(--text)}
@keyframes rowFlash{from{background:#ffffff12}to{background:transparent}}
.pkt-table tbody tr.new{animation:rowFlash .4s ease-out}
.pkt-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.pkt-counter{font-size:.7rem;color:var(--muted);margin-left:auto;font-variant-numeric:tabular-nums}
.btn-sm{font-family:inherit;font-size:.72rem;padding:5px 12px;border-radius:7px;
  border:1px solid var(--border);background:var(--surface);color:var(--text);
  cursor:pointer;transition:border-color .2s}
.btn-sm:hover{border-color:var(--accent)}
.btn-sm.active{border-color:var(--udp);color:var(--udp)}

/* ── Footer ── */
footer{padding:9px 28px;border-top:1px solid var(--border);color:var(--muted);
  font-size:.65rem;letter-spacing:1px;background:var(--surface)}

@media(max-width:700px){
  .cards{grid-template-columns:1fr 1fr}
  .charts{grid-template-columns:1fr}
}
</style>
</head>
<body>

<header>
  <div class="pulse-dot idle" id="dot"></div>
  <span class="logo">&#x2B21; Sonic</span>
  <span style="color:var(--muted);font-size:.72rem;letter-spacing:1px">Network &rarr; Music</span>
  <span class="status-badge" id="status-badge">Idle</span>
</header>

<!-- Tab bar -->
<div class="tab-bar">
  <button class="tab-btn active" data-tab="live">&#9654; Live</button>
  <button class="tab-btn"        data-tab="piano">&#127925; Piano Roll</button>
  <button class="tab-btn"        data-tab="packets">&#128225; Packets</button>
</div>

<!-- Live panel -->
<div class="panel" id="panel-live">

  <div class="controls">
    <label for="iface-select">Interface</label>
    <select id="iface-select"><option value="default">default</option></select>
    <button class="primary" id="btn-start">&#9654; Start</button>
    <button class="danger"  id="btn-stop"  disabled>&#9646;&#9646; Stop</button>
    <button id="btn-raw" title="Toggle between raw packet Hz and pentatonic harmony">&#127932; Harmony</button>
    <div class="audio-notice">
      &#127925; Audio: <span id="audio-status">click Start to unlock</span>
    </div>
  </div>

  <canvas id="viz"></canvas>

  <div class="cards">
    <div class="card c-tcp">
      <div class="card-label">TCP Packets</div>
      <div class="card-value" id="v-tcp">0</div>
      <div class="card-delta" id="d-tcp">&mdash;</div>
    </div>
    <div class="card c-udp">
      <div class="card-label">UDP Packets</div>
      <div class="card-value" id="v-udp">0</div>
      <div class="card-delta" id="d-udp">&mdash;</div>
    </div>
    <div class="card c-notes">
      <div class="card-label">Notes Played</div>
      <div class="card-value" id="v-notes">0</div>
      <div class="card-delta" id="d-notes">&mdash;</div>
    </div>
  </div>

  <div class="charts">
    <div class="chart-box">
      <h2>Packets / second</h2>
      <canvas class="chart" id="ch-pkt"></canvas>
    </div>
    <div class="chart-box">
      <h2>Notes / second</h2>
      <canvas class="chart" id="ch-notes"></canvas>
    </div>
  </div>

  <div class="log-box">
    <h2>Status log</h2>
    <div id="log"></div>
  </div>

</div><!-- /panel-live -->

<!-- Piano Roll panel -->
<div class="panel hidden" id="panel-piano">

  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
    <span style="font-size:.7rem;color:var(--muted);letter-spacing:1.5px;text-transform:uppercase">
      Scrolling piano roll &mdash; last 20 seconds
    </span>
    <div class="piano-legend">
      <div class="legend-dot" style="background:var(--tcp)"></div><span>TCP</span>
      <div class="legend-dot" style="background:var(--udp)"></div><span>UDP</span>
    </div>
  </div>

  <div class="piano-wrap">
    <canvas class="piano-keys" id="piano-keys"></canvas>
    <canvas id="piano-canvas"></canvas>
  </div>

</div><!-- /panel-piano -->

<!-- Packets panel -->
<div class="panel hidden" id="panel-packets">

  <div class="pkt-toolbar">
    <span style="font-size:.7rem;color:var(--muted);letter-spacing:1.5px;text-transform:uppercase">
      Live packet capture
    </span>
    <button class="btn-sm" id="btn-pause-pkts">&#9646;&#9646; Pause scroll</button>
    <button class="btn-sm" id="btn-clear-pkts">&#128465; Clear</button>
    <span class="pkt-counter" id="pkt-counter">0 packets</span>
  </div>

  <div class="pkt-wrap" id="pkt-wrap">
    <table class="pkt-table">
      <thead>
        <tr>
          <th>No.</th>
          <th>Time</th>
          <th>Protocol</th>
          <th>Freq&nbsp;(Hz)</th>
          <th>Note</th>
          <th>Duration&nbsp;(ms)</th>
          <th>Raw&nbsp;dur&nbsp;(ms)</th>
        </tr>
      </thead>
      <tbody id="pkt-tbody"></tbody>
    </table>
  </div>

</div><!-- /panel-packets -->

<footer>Sonic &mdash; Network Sonification &nbsp;|&nbsp; Web Audio API + libpcap</footer>

<script>
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
//  Pentatonic scale  C2–C7  (matches sonic_audio_helper.py exactly)
// ─────────────────────────────────────────────────────────────────────────────
const SCALE = (() => {
  const c2 = 65.41, ratios = [1, 9/8, 5/4, 3/2, 5/3];
  const f = [];
  for (let oct = 0; oct < 6; oct++)
    for (const r of ratios) f.push(c2 * r * Math.pow(2, oct));
  return f.sort((a, b) => a - b);
})();

// Label for each scale degree: C D E G A × 6 octaves
const SCALE_LABELS = (() => {
  const names = ['C','D','E','G','A'];
  const out = [];
  for (let oct = 0; oct < 6; oct++)
    for (const n of names) out.push(n + (oct + 2));
  return out; // index matches SCALE
})();

function snapToScale(freq) {
  return SCALE.reduce((b, f) => Math.abs(f - freq) < Math.abs(b - freq) ? f : b);
}
function scaleIndex(freq) {
  const snapped = snapToScale(freq);
  return SCALE.findIndex(f => Math.abs(f - snapped) < 0.1);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Web Audio synthesizer  (faithful port of sonic_audio_helper.py)
// ─────────────────────────────────────────────────────────────────────────────
class SonicSynth {
  constructor() { this._ctx = null; this._ready = false; this._counts = new Map(); }

  async init() {
    if (this._ready) return;
    this._ctx = new (window.AudioContext || window.webkitAudioContext)();

    this._comp = this._ctx.createDynamicsCompressor();
    this._comp.threshold.value = -18;
    this._comp.knee.value      = 8;
    this._comp.ratio.value     = 3.8;
    this._comp.attack.value    = 0.025;
    this._comp.release.value   = 0.3;
    this._comp.connect(this._ctx.destination);

    this._master = this._ctx.createGain();
    this._master.gain.value = 0.88;
    this._master.connect(this._comp);

    this._reverb = this._ctx.createConvolver();
    this._revRet = this._ctx.createGain();
    this._revRet.gain.value = 1.0;
    this._reverb.connect(this._revRet);
    this._revRet.connect(this._master);
    this._buildIR();

    if (this._ctx.state === 'suspended') await this._ctx.resume();
    this._ready = true;
  }

  _buildIR() {
    const sr = this._ctx.sampleRate, n = Math.floor(sr * 1.3);
    const buf = this._ctx.createBuffer(2, n, sr);
    const early = [
      [0.000,1.00],[0.011,0.62],[0.017,-0.52],[0.023,0.46],[0.031,-0.41],
      [0.041,0.36],[0.057,0.31],[0.071,-0.26],[0.089,0.21],[0.113,0.18],
      [0.139,-0.15],[0.167,0.12],[0.199,0.10],[0.241,0.08],[0.290,-0.07],
      [0.350,0.06],[0.420,-0.05],[0.500,0.04],
    ];
    let maxAbs = 0;
    for (let ch = 0; ch < 2; ch++) {
      const d = buf.getChannelData(ch);
      for (const [ds, amp] of early) {
        const idx = Math.floor(sr * ds);
        if (idx < n) d[idx] += amp * (ch === 0 ? 1 : 0.96 + Math.random() * 0.08);
      }
      for (let i = Math.floor(sr * 0.03); i < n; i++)
        d[i] += (Math.random() * 2 - 1) * Math.exp(-(i / sr) * 3) * 0.18;
      for (let i = 0; i < n; i++) maxAbs = Math.max(maxAbs, Math.abs(d[i]));
    }
    if (maxAbs > 0)
      for (let ch = 0; ch < 2; ch++) {
        const d = buf.getChannelData(ch);
        for (let i = 0; i < n; i++) d[i] /= maxAbs;
      }
    this._reverb.buffer = buf;
  }

  playRaw(freqHz, durationMs) {
    if (!this._ready) return;
    const ctx = this._ctx, now = ctx.currentTime;
    const dur = Math.max(0.02, Math.min(durationMs / 1000, 0.3));
    const osc = ctx.createOscillator();
    osc.type = 'sine';
    osc.frequency.value = freqHz;
    osc.connect(ctx.destination);
    osc.start(now);
    osc.stop(now + dur);
  }

  playNote(freqHz, durationMs) {
    if (!this._ready) return;
    const snapped = snapToScale(freqHz);
    const cnt = this._counts.get(snapped) || 0;
    if (cnt >= 2) return;
    this._counts.set(snapped, cnt + 1);

    const ctx = this._ctx, now = ctx.currentTime;
    const dur = Math.max(0.3, Math.min(durationMs / 1000, 7.0));
    const a = Math.min(0.30, dur * 0.12), d = Math.min(0.28, dur * 0.10),
          r = Math.min(0.90, dur * 0.32), sl = 0.70;

    const vg = ctx.createGain();
    vg.gain.setValueAtTime(0, now);
    vg.gain.linearRampToValueAtTime(1.0, now + a);
    vg.gain.linearRampToValueAtTime(sl,  now + a + d);
    vg.gain.setValueAtTime(sl, now + dur - r);
    vg.gain.linearRampToValueAtTime(0.0, now + dur);

    for (const [h, amp] of [[1,.90],[2,.38],[3,.14],[4,.06],[5,.02]]) {
      const osc = ctx.createOscillator(); osc.type = 'sine';
      osc.frequency.value = snapped * h;
      const lfo = ctx.createOscillator(); lfo.frequency.value = 5.5;
      const lg  = ctx.createGain();       lg.gain.value = snapped * h * 0.0025;
      lfo.connect(lg); lg.connect(osc.frequency);
      const hg = ctx.createGain(); hg.gain.value = amp * 0.10;
      osc.connect(hg); hg.connect(vg);
      lfo.start(now); lfo.stop(now + dur + 0.2);
      osc.start(now); osc.stop(now + dur + 0.2);
    }

    const pan = ctx.createStereoPanner(); pan.pan.value = Math.random() * 1.3 - 0.65;
    const dry = ctx.createGain();         dry.gain.value = 0.68;
    vg.connect(dry); dry.connect(pan); pan.connect(this._master);

    const snd = ctx.createGain(); snd.gain.value = 0.32;
    vg.connect(snd); snd.connect(this._reverb);

    setTimeout(() => {
      this._counts.set(snapped, Math.max(0, (this._counts.get(snapped) || 0) - 1));
    }, (dur + 0.4) * 1000);
  }

  resume() { this._ctx && this._ctx.state === 'suspended' && this._ctx.resume(); }
  get ready() { return this._ready; }
}
const synth = new SonicSynth();

// ─────────────────────────────────────────────────────────────────────────────
//  Particle / ripple visualizer  (Live tab)
// ─────────────────────────────────────────────────────────────────────────────
const vizCanvas = document.getElementById('viz');
const vc        = vizCanvas.getContext('2d');
const particles = [], ripples = [];

function resizeViz() {
  vizCanvas.width  = vizCanvas.offsetWidth  * devicePixelRatio;
  vizCanvas.height = vizCanvas.offsetHeight * devicePixelRatio;
  vc.scale(devicePixelRatio, devicePixelRatio);
}
window.addEventListener('resize', resizeViz);
resizeViz();

function spawnParticle(protocol) {
  const W = vizCanvas.offsetWidth, H = vizCanvas.offsetHeight;
  particles.push({ x: 0, y: H/2 + (Math.random()-.5)*H*.55,
    vx: 1.5+Math.random()*3, vy: (Math.random()-.5)*.6,
    color: protocol==='tcp'?'#5b9cf6':'#f6955b', size: 2+Math.random()*2, life: 1.0 });
}
function spawnRipple(protocol) {
  const W = vizCanvas.offsetWidth, H = vizCanvas.offsetHeight;
  ripples.push({ x: W*.38+Math.random()*W*.24, y: H*.15+Math.random()*H*.7,
    r: 0, maxR: 40+Math.random()*50,
    color: protocol==='tcp'?'#5b9cf6':'#f6955b', life: 1.0 });
}

function drawViz() {
  const W = vizCanvas.offsetWidth, H = vizCanvas.offsetHeight;
  vc.clearRect(0, 0, W, H);
  vc.strokeStyle = '#0d0d20'; vc.lineWidth = 1;
  for (let x = 0; x < W; x += 30) { vc.beginPath(); vc.moveTo(x,0); vc.lineTo(x,H); vc.stroke(); }
  for (let y = 0; y < H; y += 30) { vc.beginPath(); vc.moveTo(0,y); vc.lineTo(W,y); vc.stroke(); }
  vc.strokeStyle = '#18183a'; vc.lineWidth = 1;
  vc.beginPath(); vc.moveTo(0, H/2); vc.lineTo(W, H/2); vc.stroke();

  for (let i = ripples.length-1; i >= 0; i--) {
    const rp = ripples[i]; rp.r += 1.2; rp.life -= 0.013;
    if (rp.life <= 0 || rp.r > rp.maxR) { ripples.splice(i,1); continue; }
    vc.beginPath(); vc.arc(rp.x, rp.y, rp.r, 0, Math.PI*2);
    vc.strokeStyle = rp.color + Math.floor(rp.life*180).toString(16).padStart(2,'0');
    vc.lineWidth = 1.5; vc.stroke();
  }
  for (let i = particles.length-1; i >= 0; i--) {
    const p = particles[i]; p.x += p.vx; p.y += p.vy; p.life -= 0.007;
    if (p.life <= 0 || p.x > W+10) { particles.splice(i,1); continue; }
    vc.beginPath(); vc.arc(p.x, p.y, p.size, 0, Math.PI*2);
    vc.fillStyle = p.color + Math.floor(p.life*220).toString(16).padStart(2,'0');
    vc.fill();
  }
  requestAnimationFrame(drawViz);
}
drawViz();

// ─────────────────────────────────────────────────────────────────────────────
//  Piano Roll  (Piano Roll tab)
// ─────────────────────────────────────────────────────────────────────────────
const pianoCanvas = document.getElementById('piano-canvas');
const keysCanvas  = document.getElementById('piano-keys');
const pc = pianoCanvas.getContext('2d');
const kc = keysCanvas.getContext('2d');

const PIANO_WINDOW = 20;   // seconds of history visible
const pianoNotes   = [];   // {freq, duration, startTime, protocol, idx}

// Row layout: index 0 = lowest pitch (C2) at bottom, index 29 = A7 at top.
// Canvas row 0 = top → highest pitch. Canvas row (N-1) = bottom → lowest.
const N_ROWS = SCALE.length; // 30

function rowY(scaleIdx, rowH) {
  // scaleIdx 29 (highest) → row 0 (top). scaleIdx 0 (lowest) → row N_ROWS-1 (bottom).
  return (N_ROWS - 1 - scaleIdx) * rowH;
}

function resizePiano() {
  const W = pianoCanvas.offsetWidth, H = pianoCanvas.offsetHeight;
  if (W === 0 || H === 0) return;
  pianoCanvas.width  = W  * devicePixelRatio;
  pianoCanvas.height = H  * devicePixelRatio;
  pc.scale(devicePixelRatio, devicePixelRatio);

  const KW = keysCanvas.offsetWidth, KH = keysCanvas.offsetHeight;
  keysCanvas.width  = KW * devicePixelRatio;
  keysCanvas.height = KH * devicePixelRatio;
  kc.scale(devicePixelRatio, devicePixelRatio);
  drawKeys(KH);
}

function drawKeys(H) {
  const KW  = keysCanvas.offsetWidth;
  const rowH = H / N_ROWS;
  kc.clearRect(0, 0, KW, H);

  for (let i = 0; i < N_ROWS; i++) {
    const y     = rowY(i, rowH);
    const label = SCALE_LABELS[i];
    const isC   = label.startsWith('C');
    // Alternate row background
    const oct   = Math.floor(i / 5);
    kc.fillStyle = oct % 2 === 0 ? '#0c0c18' : '#0a0a14';
    kc.fillRect(0, y, KW, rowH);

    if (rowH >= 10) {
      kc.font        = `${Math.min(9, rowH * 0.75)}px 'SF Mono', monospace`;
      kc.fillStyle   = isC ? '#8888aa' : '#444455';
      kc.textAlign   = 'right';
      kc.textBaseline = 'middle';
      kc.fillText(label, KW - 4, y + rowH / 2);
    }

    // Separator line
    kc.strokeStyle = '#111120'; kc.lineWidth = 0.5;
    kc.beginPath(); kc.moveTo(0, y); kc.lineTo(KW, y); kc.stroke();
  }
}

function drawPianoRoll() {
  const W = pianoCanvas.offsetWidth, H = pianoCanvas.offsetHeight;
  if (W === 0 || H === 0) { requestAnimationFrame(drawPianoRoll); return; }
  const rowH  = H / N_ROWS;
  const now   = performance.now() / 1000;

  pc.clearRect(0, 0, W, H);

  // Octave band backgrounds
  for (let oct = 0; oct < 6; oct++) {
    const topIdx    = oct * 5 + 4;          // A of this octave (highest in octave)
    const bottomIdx = oct * 5;              // C of this octave
    const yTop      = rowY(topIdx, rowH);
    const yBot      = rowY(bottomIdx, rowH) + rowH;
    pc.fillStyle = oct % 2 === 0 ? '#09091a' : '#07070f';
    pc.fillRect(0, yTop, W, yBot - yTop);
  }

  // Vertical time grid lines (every 2 seconds)
  pc.strokeStyle = '#111128'; pc.lineWidth = 1;
  for (let t = 0; t < PIANO_WINDOW; t += 2) {
    const x = W * (1 - t / PIANO_WINDOW);
    pc.beginPath(); pc.moveTo(x, 0); pc.lineTo(x, H); pc.stroke();
    if (t > 0) {
      pc.fillStyle = '#22223a'; pc.font = '9px monospace'; pc.textAlign = 'center';
      pc.fillText(`−${t}s`, x, H - 4);
    }
  }

  // Horizontal row separators
  for (let i = 0; i < N_ROWS; i++) {
    const y = rowY(i, rowH);
    pc.strokeStyle = '#0f0f22'; pc.lineWidth = 0.5;
    pc.beginPath(); pc.moveTo(0, y); pc.lineTo(W, y); pc.stroke();
    // Brighter line at each C (octave boundary)
    if (SCALE_LABELS[i].startsWith('C')) {
      pc.strokeStyle = '#1e1e36'; pc.lineWidth = 1;
      pc.beginPath(); pc.moveTo(0, y); pc.lineTo(W, y); pc.stroke();
    }
  }

  // Draw notes
  const cutoff = now - PIANO_WINDOW - 2;
  for (let i = pianoNotes.length - 1; i >= 0; i--) {
    const n = pianoNotes[i];
    if (n.startTime < cutoff) { pianoNotes.splice(i, 1); continue; }

    const age   = now - n.startTime;
    const xEnd  = W * (1 - age / PIANO_WINDOW);
    const xStart = W * (1 - (age + n.duration) / PIANO_WINDOW);
    const barW  = Math.max(3, xEnd - xStart);
    const y     = rowY(n.idx, rowH) + rowH * 0.08;
    const barH  = rowH * 0.84;

    // Fade out as note approaches left edge
    const alpha = Math.max(0, Math.min(1, xEnd / (W * 0.08)));
    const color = n.protocol === 'tcp' ? '91,156,246' : '246,149,91';

    // Gradient fill
    const grad = pc.createLinearGradient(xStart, 0, xEnd, 0);
    grad.addColorStop(0, `rgba(${color},${(0.25 * alpha).toFixed(2)})`);
    grad.addColorStop(1, `rgba(${color},${(0.85 * alpha).toFixed(2)})`);
    pc.fillStyle = grad;
    const radius = Math.min(3, barH / 2, barW / 2);
    pc.beginPath();
    pc.roundRect(xStart, y, barW, barH, radius);
    pc.fill();

    // Top highlight stripe
    pc.fillStyle = `rgba(${color},${(0.35 * alpha).toFixed(2)})`;
    pc.fillRect(xStart, y, barW, Math.min(2, barH * 0.2));
  }

  // "Now" marker line
  pc.strokeStyle = '#ffffff18'; pc.lineWidth = 1.5;
  pc.setLineDash([4, 4]);
  pc.beginPath(); pc.moveTo(W, 0); pc.lineTo(W, H); pc.stroke();
  pc.setLineDash([]);

  requestAnimationFrame(drawPianoRoll);
}

window.addEventListener('resize', resizePiano);
// Init after layout is ready
setTimeout(() => { resizePiano(); drawPianoRoll(); }, 100);

// ─────────────────────────────────────────────────────────────────────────────
//  Tab switching
// ─────────────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.tab).classList.remove('hidden');
    if (btn.dataset.tab === 'piano') setTimeout(resizePiano, 50);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  Chart.js
// ─────────────────────────────────────────────────────────────────────────────
const chartCfg = {
  animation: false, responsive: true, maintainAspectRatio: true,
  interaction: { mode: 'index', intersect: false },
  scales: {
    x: { ticks: { color: '#44445a', maxTicksLimit: 8 }, grid: { color: '#111128' } },
    y: { ticks: { color: '#44445a' }, grid: { color: '#111128' }, beginAtZero: true },
  },
  plugins: { legend: { labels: { color: '#66667a', boxWidth: 10, padding: 14 } } },
};
const ds = (label, color) => ({
  label, data: [], borderColor: color, backgroundColor: color+'22',
  borderWidth: 1.8, pointRadius: 0, tension: 0.38, fill: true,
});
const chPkt   = new Chart(document.getElementById('ch-pkt'),
  { type:'line', data:{ labels:[], datasets:[ds('TCP','#5b9cf6'), ds('UDP','#f6955b')] }, options:{...chartCfg} });
const chNotes = new Chart(document.getElementById('ch-notes'),
  { type:'line', data:{ labels:[], datasets:[ds('Notes/s','#4df6a0')] }, options:{...chartCfg} });

setInterval(async () => {
  try {
    const r = await fetch('/api/metrics'); if (!r.ok) return;
    const s = await r.json();
    document.getElementById('v-tcp').textContent   = s.totals.tcp.toLocaleString();
    document.getElementById('v-udp').textContent   = s.totals.udp.toLocaleString();
    document.getElementById('v-notes').textContent = s.totals.notes.toLocaleString();
    const last = k => s[k] && s[k].length ? s[k][s[k].length-1] : 0;
    document.getElementById('d-tcp').textContent   = `+${last('tcp')}/s`;
    document.getElementById('d-udp').textContent   = `+${last('udp')}/s`;
    document.getElementById('d-notes').textContent = `+${last('notes')}/s`;
    chPkt.data.labels = chNotes.data.labels = s.labels;
    chPkt.data.datasets[0].data   = s.tcp;
    chPkt.data.datasets[1].data   = s.udp;
    chNotes.data.datasets[0].data = s.notes;
    chPkt.update('none'); chNotes.update('none');
  } catch(_) {}
}, 1500);

// ─────────────────────────────────────────────────────────────────────────────
//  UI helpers
// ─────────────────────────────────────────────────────────────────────────────
function setRunning(running) {
  const dot = document.getElementById('dot'), badge = document.getElementById('status-badge');
  dot.className   = 'pulse-dot ' + (running ? 'active' : 'idle');
  badge.className = 'status-badge ' + (running ? 'running' : '');
  badge.textContent = running ? 'Capturing' : 'Idle';
  document.getElementById('btn-start').disabled = running;
  document.getElementById('btn-stop').disabled  = !running;
}
function addLog(msg) {
  const log = document.getElementById('log');
  const div = document.createElement('div'); div.className = 'entry';
  div.textContent = `[${new Date().toLocaleTimeString([],{hour12:false})}]  ${msg}`;
  log.appendChild(div); log.scrollTop = log.scrollHeight;
  while (log.children.length > 80) log.removeChild(log.firstChild);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Socket.io
// ─────────────────────────────────────────────────────────────────────────────
const socket = io();
socket.on('connect',    () => addLog('Socket connected.'));
socket.on('disconnect', () => { addLog('Socket disconnected.'); setRunning(false); });
socket.on('log',    e  => addLog(e.msg));
socket.on('status', e  => setRunning(e.running));

// ── Raw / Harmony toggle ──────────────────────────────────────────────────────
let rawMode = false;
const btnRaw = document.getElementById('btn-raw');
btnRaw.addEventListener('click', () => {
  rawMode = !rawMode;
  btnRaw.textContent = rawMode ? '⚡ Raw Hz' : '♜ Harmony';
  btnRaw.classList.toggle('raw-mode', rawMode);
});

socket.on('note', async e => {
  if (!synth.ready) {
    await synth.init();
    document.getElementById('audio-status').textContent = 'active';
  }
  synth.resume();
  if (rawMode) synth.playRaw(e.freq, e.duration);
  else         synth.playNote(e.freq, e.duration);
  spawnParticle(e.protocol);
  spawnRipple(e.protocol);

  // Piano roll entry
  const idx = scaleIndex(e.freq);
  if (idx !== -1) {
    pianoNotes.push({
      freq:      e.freq,
      duration:  e.duration / 1000,
      startTime: performance.now() / 1000,
      protocol:  e.protocol,
      idx,
    });
  }

  // Packet table entry
  document.dispatchEvent(new CustomEvent('sonic-note', { detail: e }));
});

// ─────────────────────────────────────────────────────────────────────────────
//  Controls
// ─────────────────────────────────────────────────────────────────────────────
fetch('/api/interfaces')
  .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
  .then(ifaces => {
    const sel = document.getElementById('iface-select');
    sel.innerHTML = '';
    for (const iface of ifaces) {
      const opt = document.createElement('option');
      opt.value = iface;
      opt.textContent = iface === 'en0' ? 'en0  (Wi-Fi)' : iface;
      if (iface === 'en0') opt.selected = true;
      sel.appendChild(opt);
    }
    // auto-select en0 (Wi-Fi on Mac) if present, otherwise fall back to "default"
    if (!ifaces.includes('en0')) sel.value = 'default';
  })
  .catch(e => addLog('⚠ Could not load interfaces: ' + e));

document.getElementById('btn-start').addEventListener('click', async () => {
  if (!synth.ready) {
    await synth.init();
    document.getElementById('audio-status').textContent = 'ready';
  }
  socket.emit('start', { interface: document.getElementById('iface-select').value });
});

document.getElementById('btn-stop').addEventListener('click', () => {
  socket.emit('stop');
});

// ─────────────────────────────────────────────────────────────────────────────
//  Packet table  (Packets tab)
// ─────────────────────────────────────────────────────────────────────────────
let pktCount    = 0;
let pktPaused   = false;
const MAX_ROWS  = 500;
const pktTbody  = document.getElementById('pkt-tbody');
const pktWrap   = document.getElementById('pkt-wrap');
const pktCounter = document.getElementById('pkt-counter');

function freqToNoteName(freq) {
  const snapped = snapToScale(freq);
  const idx = SCALE.findIndex(f => Math.abs(f - snapped) < 0.1);
  return idx !== -1 ? SCALE_LABELS[idx] : '?';
}

function addPacketRow(e) {
  pktCount++;
  pktCounter.textContent = pktCount.toLocaleString() + ' packets';

  const tr = document.createElement('tr');
  tr.className = (e.protocol === 'tcp' ? 'tcp' : 'udp') + ' new';

  const ts  = new Date().toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 2 });
  const note = freqToNoteName(e.freq);

  tr.innerHTML = `
    <td>${pktCount}</td>
    <td>${ts}</td>
    <td>${e.protocol.toUpperCase()}</td>
    <td>${e.freq.toFixed(1)}</td>
    <td>${note}</td>
    <td>${e.duration}</td>
    <td>${e.raw_duration ?? '—'}</td>
  `;

  pktTbody.appendChild(tr);

  // Keep table bounded
  while (pktTbody.rows.length > MAX_ROWS) pktTbody.deleteRow(0);

  // Remove flash class after animation
  tr.addEventListener('animationend', () => tr.classList.remove('new'), { once: true });

  // Auto-scroll to bottom unless paused
  if (!pktPaused) pktWrap.scrollTop = pktWrap.scrollHeight;
}

document.getElementById('btn-pause-pkts').addEventListener('click', function() {
  pktPaused = !pktPaused;
  this.textContent = pktPaused ? '▶ Resume scroll' : '⏸ Pause scroll';
  this.classList.toggle('active', pktPaused);
});

document.getElementById('btn-clear-pkts').addEventListener('click', () => {
  pktTbody.innerHTML = '';
  pktCount = 0;
  pktCounter.textContent = '0 packets';
});

// Hook into the existing note handler — packet rows are added there too.
// We use a custom event so we don't duplicate the socket.on('note') handler.
document.addEventListener('sonic-note', e => addPacketRow(e.detail));
</script>
</body>
</html>
"""


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]
    port = WEB_PORT
    for i, a in enumerate(args):
        if a.startswith("--port="):
            port = int(a.split("=")[1])
        elif a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])

    _start_sampler()

    print(f"\n  Sonic Web Server")
    print(f"  Open  \u2192  http://localhost:{port}\n")
    print("  Audio plays in your browser (Web Audio API).")
    print("  sudo password may be required in this terminal when capture starts.\n")

    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
