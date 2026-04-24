# Sonic — Network to Music

Converts live TCP/UDP network packets into music in real time.  
Packet capture is done in C (libpcap); audio runs entirely in your browser via the Web Audio API.

## How to Run

### Requirements
- macOS with Python 3 installed (`python3 --version` to check)


### Steps

```bash
# 1. Clone the repo
git clone https://github.com/sebastianfeliciano/sonic.git
cd sonic

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Compile the C packet processor
make

# 4. Start the server
python3 sonic_server.py
```

5. Open **http://localhost:8080** in your browser
6. Click **▶ Start** — you will be prompted for your macOS password **once** to allow packet capture
7. Music plays!

---

## What it does

- Captures live TCP and UDP packets on your network interface using **libpcap**
- Maps each packet's destination port and protocol to a musical frequency (pentatonic scale)
- TCP packets → lower octave, UDP packets → higher octave
- Duration is proportional to the IP payload size
- Audio is synthesized in the browser with ADSR envelopes, harmonics, reverb, and stereo panning

## Tabs

| Tab | Description |
|---|---|
| **Live** | Particle visualizer + packet rate charts + status log |
| **Piano Roll** | Scrolling piano roll showing the last 20 seconds of notes |
| **Packets** | Live packet table with protocol, frequency, note name, and duration |

## Architecture

```
packet_processor.c  →  stdout (NOTE lines)  →  sonic_server.py  →  browser (Web Audio API)
     (libpcap / C)                               (Flask + SocketIO)
```

- `packet_processor.c` — C program that opens the network interface and emits `NOTE <proto> <hz> <ms>` lines
- `sonic_server.py` — Flask + SocketIO web server; relays notes to the browser
- `sonic_gui.py` — Optional tkinter GUI (alternative to the web UI)
- `sonic_audio_helper.py` — Local audio synthesis via sounddevice (used by the GUI)
- `sonic_priv.py` — Handles one-time privilege setup for packet capture

## Stopping

Press `Ctrl-C` in the terminal to stop the server.
