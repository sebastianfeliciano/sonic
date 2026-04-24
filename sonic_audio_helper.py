#!/usr/bin/env python3
"""
Sonic audio helper — high-quality polyphonic pad synthesizer.

  ✦ Frequencies snapped to C pentatonic scale  → always consonant chords
  ✦ Additive synthesis: fundamental + harmonics with natural decay
  ✦ FM-style vibrato (5.5 Hz, ±0.25%) for warmth
  ✦ Full cosine ADSR — slow bloom attack, long release
  ✦ Convolution reverb (synthetic room IR, ~1.3 s)
  ✦ Haas stereo width: short comb delay on one channel + random pan
  ✦ Note deduplication: max 2 of the same pitch at once (no muddy stacking)
  ✦ RMS compressor on master bus — volume breathes naturally with traffic
  ✦ Soft-clip (tanh) output limiter
"""

import sys
import threading
import time
import math
import random

SAMPLE_RATE     = 44100
BLOCK_SIZE      = 512
MAX_DURATION_MS = 7000
MAX_VOICES      = 20     # sweet spot: rich but not muddy
VOICE_VOLUME    = 0.10

# ── Pentatonic scale C2 – C7 ─────────────────────────────────────────────────

def _build_scale() -> list:
    c2     = 65.41
    ratios = [1, 9/8, 5/4, 3/2, 5/3]   # C D E G A
    freqs  = []
    for octave in range(6):
        for r in ratios:
            freqs.append(c2 * r * (2 ** octave))
    return sorted(freqs)

SCALE = _build_scale()

def snap_to_scale(freq: float) -> float:
    return min(SCALE, key=lambda f: abs(f - freq))


# ── Reverb IR ─────────────────────────────────────────────────────────────────

_IR_CACHE = None

def _get_ir():
    global _IR_CACHE
    if _IR_CACHE is not None:
        return _IR_CACHE
    import numpy as np

    sr, dur = SAMPLE_RATE, 1.3
    n       = int(sr * dur)
    ir      = np.zeros(n, dtype=np.float64)

    early = [
        (0.000,  1.00), (0.011,  0.62), (0.017, -0.52),
        (0.023,  0.46), (0.031, -0.41), (0.041,  0.36),
        (0.057,  0.31), (0.071, -0.26), (0.089,  0.21),
        (0.113,  0.18), (0.139, -0.15), (0.167,  0.12),
        (0.199,  0.10), (0.241,  0.08), (0.290, -0.07),
        (0.350,  0.06), (0.420, -0.05), (0.500,  0.04),
    ]
    for delay_s, amp in early:
        idx = int(sr * delay_s)
        if idx < n:
            ir[idx] += amp

    t   = np.arange(n) / sr
    rng = np.random.default_rng(42)
    tail = rng.standard_normal(n) * np.exp(-t * 3.0)
    tail[:int(sr * 0.03)] = 0.0
    ir += tail * 0.18

    smooth = np.ones(8, dtype=np.float64) / 8.0
    ir = np.convolve(ir, smooth, mode='same')
    ir /= np.max(np.abs(ir)) + 1e-9
    _IR_CACHE = ir.astype(np.float32)
    return _IR_CACHE


def _apply_reverb(audio: "np.ndarray", wet: float = 0.32) -> "np.ndarray":
    import numpy as np
    ir      = _get_ir()
    n_total = len(audio) + len(ir) - 1
    n_fft   = 1
    while n_fft < n_total:
        n_fft <<= 1
    A = np.fft.rfft(audio.astype(np.float64), n_fft)
    B = np.fft.rfft(ir.astype(np.float64),    n_fft)
    wet_sig = np.fft.irfft(A * B, n_fft)[:n_total].astype(np.float32)
    dry     = np.zeros(n_total, dtype=np.float32)
    dry[:len(audio)] = audio
    return (dry * (1.0 - wet) + wet_sig * wet).astype(np.float32)


# ── Voice synthesis ───────────────────────────────────────────────────────────

# Softer harmonic rolloff → warm pad, not buzzy organ
HARMONICS = [(1, 0.90), (2, 0.38), (3, 0.14), (4, 0.06), (5, 0.02)]


def make_tone(freq_hz: float, duration_ms: int,
              pan: float = 0.0) -> "tuple[np.ndarray, np.ndarray]":
    """
    Returns (left, right) float32 arrays including full reverb tail.
    Stereo width comes from random pan + a short Haas delay on one channel.
    """
    import numpy as np

    freq_hz     = snap_to_scale(freq_hz)
    duration_ms = max(300, min(int(duration_ms), MAX_DURATION_MS))
    n           = int(SAMPLE_RATE * duration_ms / 1000.0)
    t           = np.arange(n, dtype=np.float64) / SAMPLE_RATE

    # FM vibrato — correct phase-integral formulation
    vib_rate  = 5.5
    vib_depth = 0.0025
    vib_base  = (freq_hz * vib_depth / vib_rate) * (1.0 - np.cos(2.0 * np.pi * vib_rate * t))

    # Additive synthesis with per-harmonic natural decay
    wave = np.zeros(n, dtype=np.float64)
    for h, amp in HARMONICS:
        harm_decay = np.exp(-t * (0.15 + h * 0.28))
        phase      = 2.0 * np.pi * freq_hz * h * t + h * vib_base
        wave      += amp * harm_decay * np.sin(phase)

    # ADSR — slow bloom (up to 300 ms attack) + long release
    a_ms = min(300.0, duration_ms * 0.12)   # bloom in gently
    d_ms = min(280.0, duration_ms * 0.10)
    r_ms = min(900.0, duration_ms * 0.32)   # long fade out
    sl   = 0.70

    a_s = max(1, int(SAMPLE_RATE * a_ms / 1000.0))
    d_s = max(1, int(SAMPLE_RATE * d_ms / 1000.0))
    r_s = max(1, int(SAMPLE_RATE * r_ms / 1000.0))
    a_s = min(a_s, n)
    d_s = min(d_s, max(1, n - a_s))
    r_s = min(r_s, max(1, n - a_s - d_s))
    s_s = max(0, n - a_s - d_s - r_s)

    env = np.zeros(n, dtype=np.float64)
    env[:a_s]                         = 0.5 - 0.5 * np.cos(np.pi * np.linspace(0.0, 1.0, a_s))
    env[a_s:a_s + d_s]                = 1.0 - (1.0 - sl) * (
        0.5 - 0.5 * np.cos(np.pi * np.linspace(0.0, 1.0, d_s))
    )
    if s_s:
        env[a_s + d_s:a_s + d_s + s_s] = sl
    if r_s:
        env[n - r_s:] = sl * (0.5 + 0.5 * np.cos(np.pi * np.linspace(0.0, 1.0, r_s)))

    mono = (VOICE_VOLUME * env * wave).astype(np.float32)
    mono = _apply_reverb(mono)

    # Haas stereo: short comb delay (4–11 ms) on one channel widens the image
    delay_samp = random.randint(int(SAMPLE_RATE * 0.004), int(SAMPLE_RATE * 0.011))
    wide = np.zeros_like(mono)
    wide[delay_samp:] = mono[: len(mono) - delay_samp]

    # Random panning: which channel gets the delay also randomised
    pan  = max(-1.0, min(1.0, pan))
    vl   = math.sqrt(max(0.0, (1.0 - pan) / 2.0))
    vr   = math.sqrt(max(0.0, (1.0 + pan) / 2.0))

    if random.random() < 0.5:
        return mono * vl, wide * vr
    else:
        return wide * vl, mono * vr


# ── RMS compressor ────────────────────────────────────────────────────────────

class Compressor:
    """
    Block-level RMS compressor.
    Automatically rides the master volume so dense traffic never overwhelms
    and sparse notes stay present and audible.
    """
    def __init__(self,
                 threshold: float = 0.26,
                 ratio: float     = 3.8,
                 attack_ms: float = 25.0,
                 release_ms: float= 300.0,
                 makeup: float    = 1.12):
        self._threshold = threshold
        self._ratio     = ratio
        self._makeup    = makeup
        self._env       = 0.0
        sr = SAMPLE_RATE
        self._atk = math.exp(-1.0 / (sr * attack_ms  / 1000.0))
        self._rel = math.exp(-1.0 / (sr * release_ms / 1000.0))

    def process(self, left: "np.ndarray", right: "np.ndarray"):
        import numpy as np
        # RMS level of mid signal
        mid  = (left + right) * 0.5
        rms  = math.sqrt(max(float(np.mean(mid * mid)), 1e-12))
        coef = self._atk if rms > self._env else self._rel
        self._env = coef * self._env + (1.0 - coef) * rms

        if self._env > self._threshold:
            over   = self._env - self._threshold
            reduced = self._threshold + over / self._ratio
            gain   = (reduced / self._env) * self._makeup
        else:
            gain = self._makeup

        gain = min(gain, 1.6)   # cap makeup so silence never gets boosted too loud
        g = float(gain)
        return left * g, right * g


# ── Polyphonic stereo mixer ───────────────────────────────────────────────────

class Mixer:
    def __init__(self):
        # Each entry: [pos, left, right, snapped_freq]
        self._voices: list = []
        self._lock   = threading.Lock()
        self._comp   = Compressor()

    def add(self, left: "np.ndarray", right: "np.ndarray",
            freq_hz: float = 0.0) -> None:
        with self._lock:
            # Deduplication: allow at most 2 voices per pitch
            same = sum(
                1 for v in self._voices
                if abs(v[3] - freq_hz) / max(freq_hz, 1.0) < 0.02
            )
            if same >= 2:
                return
            while len(self._voices) >= MAX_VOICES:
                self._voices.pop(0)
            self._voices.append([0, left, right, freq_hz])

    def callback(self, outdata, frames, time_info, status) -> None:
        import numpy as np

        out_l = np.zeros(frames, dtype=np.float32)
        out_r = np.zeros(frames, dtype=np.float32)
        with self._lock:
            remaining = []
            for pos, left, right, freq in self._voices:
                take = min(frames, len(left) - pos)
                if take <= 0:
                    continue
                out_l[:take] += left[pos:pos + take]
                out_r[:take] += right[pos:pos + take]
                pos += take
                if pos < len(left):
                    remaining.append([pos, left, right, freq])
            self._voices = remaining

        # Compress → soft-clip → output
        out_l, out_r = self._comp.process(out_l, out_r)
        outdata[:, 0] = np.tanh(out_l * 1.2) * 0.92
        outdata[:, 1] = np.tanh(out_r * 1.2) * 0.92

    def pending(self) -> bool:
        with self._lock:
            return bool(self._voices)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        import sounddevice as sd
        d = sd.query_devices(kind="output")
        print(getattr(d, "name", "?"),
              getattr(d, "max_output_channels", "?"),
              getattr(d, "default_samplerate", "?"))
        return

    import numpy as np
    import sounddevice as sd

    _get_ir()   # warm up reverb cache before first note

    mixer      = Mixer()
    stdin_done = threading.Event()

    def stdin_loop() -> None:
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                try:
                    freq        = float(parts[0])
                    duration_ms = int(parts[1])
                except (ValueError, IndexError):
                    continue
                pan        = random.uniform(-0.65, 0.65)
                snapped    = snap_to_scale(freq)
                left, right = make_tone(freq, duration_ms, pan)
                mixer.add(left, right, snapped)
        except Exception:
            pass
        finally:
            stdin_done.set()

    threading.Thread(target=stdin_loop, daemon=True).start()

    stream_kw = dict(
        samplerate=SAMPLE_RATE,
        channels=2,
        dtype="float32",
        blocksize=BLOCK_SIZE,
        callback=mixer.callback,
    )

    def _drain():
        for _ in range(800):
            if not mixer.pending():
                break
            time.sleep(0.01)

    try:
        with sd.OutputStream(**stream_kw):
            while not stdin_done.is_set():
                time.sleep(0.05)
            _drain()
    except Exception as e:
        print(f"Stereo failed ({e}), retrying mono…", file=sys.stderr)
        stream_kw["channels"] = 1

        def mono_cb(outdata, frames, ti, st):
            tmp = np.zeros((frames, 2), dtype=np.float32)
            mixer.callback(tmp, frames, ti, st)
            outdata[:, 0] = (tmp[:, 0] + tmp[:, 1]) * 0.5

        stream_kw["callback"] = mono_cb
        stdin_done.clear()
        with sd.OutputStream(**stream_kw):
            while not stdin_done.is_set():
                time.sleep(0.05)
            _drain()


if __name__ == "__main__":
    main()
