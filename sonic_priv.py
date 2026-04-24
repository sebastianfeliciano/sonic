#!/usr/bin/env python3
"""
sonic_priv.py — one-time privilege setup for packet capture on macOS.

Uses the same mechanism as Wireshark (ChmodBPF / access_bpf group):
  1. Adds the current user to the 'access_bpf' group   (permanent)
  2. Makes /dev/bpf* readable by that group             (per-boot)
  3. Installs a tiny LaunchDaemon to repeat step 2 on every boot  (permanent)

After this one-time setup the packet_processor binary runs as a normal user
with no sudo, no setuid bit, and no password prompts.


Why not chown/chmod u+s?  macOS Sequoia (15.x) refuses 'chown root:wheel'
even through osascript administrator privileges for files in ~/Desktop.
BPF device permissions are not subject to that restriction.
"""
from __future__ import annotations

import grp
import os
import pwd
import stat
import subprocess
import sys
import textwrap

# ── Path for the per-boot LaunchDaemon we install ────────────────────────────
_LAUNCH_DAEMON_LABEL = "com.sonic.chmodbpf"
_LAUNCH_DAEMON_PLIST = f"/Library/LaunchDaemons/{_LAUNCH_DAEMON_LABEL}.plist"
_CHMODBPF_SCRIPT     = "/Library/Application Support/Sonic/ChmodBPF"


# ── Public API ────────────────────────────────────────────────────────────────

def bpf_accessible() -> bool:
    """Return True if the current process can already open /dev/bpf0."""
    return os.access("/dev/bpf0", os.R_OK | os.W_OK)


def ensure_bpf_access(parent_window=None) -> bool:
    """
    Grant the current user permanent access to /dev/bpf* so that
    packet_processor can capture without sudo.

    Steps (all in one osascript call — single password prompt):
      • Add user to 'access_bpf' group
      • chmod/chgrp /dev/bpf* right now
      • Install /Library/LaunchDaemons/com.sonic.chmodbpf.plist so the
        chmod runs automatically on every subsequent boot

    Returns True if BPF is now accessible, False if the user cancelled
    or something went wrong.
    """
    if bpf_accessible():
        return True

    username = pwd.getpwuid(os.getuid()).pw_name

    # The script we install as a LaunchDaemon
    chmodbpf_sh = textwrap.dedent("""\
        #!/bin/sh
        chmod g+rw /dev/bpf*
        chgrp access_bpf /dev/bpf*
    """)

    # LaunchDaemon plist (runs ChmodBPF at every boot, root context)
    plist_xml = textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>{_LAUNCH_DAEMON_LABEL}</string>
            <key>ProgramArguments</key>
            <array>
                <string>{_CHMODBPF_SCRIPT}</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
        </dict>
        </plist>
    """).strip()

    # Build a single shell script that does everything in one sudo invocation
    setup_sh = f"""
set -e
# 1. Create ChmodBPF helper
mkdir -p '/Library/Application Support/Sonic'
cat > '{_CHMODBPF_SCRIPT}' << 'EOSH'
{chmodbpf_sh}EOSH
chmod +x '{_CHMODBPF_SCRIPT}'

# 2. Install LaunchDaemon
cat > '{_LAUNCH_DAEMON_PLIST}' << 'EOPLIST'
{plist_xml}
EOPLIST

# 3. Load (or reload) the daemon
launchctl unload '{_LAUNCH_DAEMON_PLIST}' 2>/dev/null || true
launchctl load  '{_LAUNCH_DAEMON_PLIST}'

# 4. Run ChmodBPF immediately so we don't have to reboot
'{_CHMODBPF_SCRIPT}'

# 5. Add current user to access_bpf group
dseditgroup -o edit -a '{username}' -t user access_bpf 2>/dev/null || true
""".strip()

    applescript = (
        'do shell script '
        + repr(setup_sh)
        + ' with prompt "Sonic needs one-time permission to capture network '
        + 'packets (same as Wireshark)." with administrator privileges'
    )

    _info(parent_window,
          "One-time setup",
          "Sonic needs to install a packet-capture helper (same mechanism "
          "as Wireshark).\n\nYou will see one macOS password prompt — this "
          "never happens again.")

    try:
        result = subprocess.run(
            ["osascript", "-e", applescript],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        return _try_sudo_setup(username, chmodbpf_sh, plist_xml, parent_window)
    except subprocess.TimeoutExpired:
        _warn(parent_window, "Timeout", "Password dialog timed out.")
        return False

    if result.returncode != 0:
        err = result.stderr.strip()
        if "(-128)" in err or "User canceled" in err:
            _warn(parent_window, "Cancelled",
                  "Setup was cancelled.\n\n"
                  "Sonic cannot capture packets without this step.")
        else:
            _warn(parent_window, "Setup failed",
                  f"Could not install capture helper:\n{err}\n\n"
                  "Try running the launcher script instead — it uses "
                  "a plain 'sudo' prompt which always works.")
        return False

    # Give the kernel a moment to apply permissions
    import time; time.sleep(0.5)
    return bpf_accessible()


# ── Fallback (Linux / non-macOS) ──────────────────────────────────────────────

def _try_sudo_setup(username, chmodbpf_sh, plist_xml, parent_window) -> bool:
    """Fall back to plain sudo in the terminal for non-macOS."""
    try:
        r = subprocess.run(
            ["sudo", "sh", "-c",
             f"chmod g+rw /dev/bpf* && chgrp access_bpf /dev/bpf* && "
             f"dseditgroup -o edit -a '{username}' -t user access_bpf 2>/dev/null || true"],
            timeout=60,
        )
        import time; time.sleep(0.3)
        return r.returncode == 0 and bpf_accessible()
    except Exception:
        return False


# ── Backward-compat shim (existing callers that used ensure_setuid) ───────────

def ensure_setuid(binary_path: str, parent_window=None) -> bool:
    """Deprecated shim — delegates to ensure_bpf_access."""
    return ensure_bpf_access(parent_window=parent_window)


def _has_setuid_root(path: str) -> bool:
    """Return True if the binary already has the setuid-root bit set."""
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_ISUID) and st.st_uid == 0
    except Exception:
        return False


# ── UI helpers ────────────────────────────────────────────────────────────────

def _info(parent_window, title: str, message: str) -> None:
    if parent_window is not None:
        try:
            import tkinter.messagebox as mb  # type: ignore
            mb.showinfo(title, message, parent=parent_window)
            return
        except Exception:
            pass
    print(f"[Sonic] {title}: {message}", file=sys.stderr)


def _warn(parent_window, title: str, message: str) -> None:
    if parent_window is not None:
        try:
            import tkinter.messagebox as mb  # type: ignore
            mb.showwarning(title, message, parent=parent_window)
            return
        except Exception:
            pass
    print(f"[Sonic] WARNING — {title}: {message}", file=sys.stderr)
