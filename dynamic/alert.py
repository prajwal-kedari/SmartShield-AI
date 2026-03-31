# alert_handler.py
# Handles confirmed malware detections.
#
# On each .fire() call it:
#   1. Prints a red console alert with all context
#   2. Attempts to terminate the offending PID
#   3. Appends a JSON record to alerts/YYYY-MM-DD.jsonl
#
# Import this in process_monitor.py — do not run standalone.

import os
import json
import time
import datetime
import psutil   # pip install psutil


class AlertHandler:

    ALERTS_DIR = "alerts"
    RED        = "\033[91m"
    YELLOW     = "\033[93m"
    RESET      = "\033[0m"
    BOLD       = "\033[1m"

    def __init__(self):
        os.makedirs(self.ALERTS_DIR, exist_ok=True)

    # ── Public entry point ───────────────────────────────────────────────────
    def fire(self, pid: int, exe_path: str, prob: float,
             gate: str, features: dict):
        """
        Called by ProcessMonitor on a confirmed detection.

        pid      — process ID to terminate
        exe_path — full path to the executable
        prob     — malware probability (0–1)
        gate     — "static_pe" or "behavioral"
        features — dict of non-zero feature values (for logging)
        """
        ts = datetime.datetime.now().isoformat(timespec="seconds")

        self._print_alert(ts, pid, exe_path, prob, gate)
        terminated = self._kill(pid)
        self._log(ts, pid, exe_path, prob, gate, features, terminated)

    # ── Console output ───────────────────────────────────────────────────────
    def _print_alert(self, ts, pid, exe_path, prob, gate):
        bar = "=" * 60
        print(f"\n{self.RED}{self.BOLD}{bar}")
        print(f"  MALWARE DETECTED  [{gate.upper()}]")
        print(bar)
        print(f"  Time     : {ts}")
        print(f"  PID      : {pid}")
        print(f"  Path     : {exe_path or '(unknown)'}")
        print(f"  Prob     : {prob:.3f}  (threshold {0.55})")
        print(f"{bar}{self.RESET}\n")

    # ── Process termination ──────────────────────────────────────────────────
    def _kill(self, pid: int) -> bool:
        """
        Attempts to terminate the process.
        Returns True if successfully terminated.
        """
        if pid <= 4:   # never kill System Idle or System
            return False
        try:
            proc = psutil.Process(pid)
            proc.terminate()          # SIGTERM first (graceful)
            time.sleep(0.5)

            if proc.is_running():
                proc.kill()           # SIGKILL if still alive

            print(f"{self.YELLOW}[AlertHandler] PID {pid} terminated.{self.RESET}")
            return True

        except psutil.NoSuchProcess:
            print(f"[AlertHandler] PID {pid} already exited.")
            return False
        except psutil.AccessDenied:
            print(f"{self.YELLOW}[AlertHandler] PID {pid} — access denied. "
                  f"Run as Administrator.{self.RESET}")
            return False
        except Exception as e:
            print(f"[AlertHandler] Could not kill PID {pid}: {e}")
            return False

    # ── JSON logging ─────────────────────────────────────────────────────────
    def _log(self, ts, pid, exe_path, prob, gate, features, terminated):
        """
        Appends one JSON line per alert to alerts/YYYY-MM-DD.jsonl
        Each line is a self-contained record — easy to parse with pandas later.
        """
        record = {
            "timestamp"  : ts,
            "pid"        : pid,
            "exe_path"   : exe_path,
            "probability": round(prob, 4),
            "gate"       : gate,
            "terminated" : terminated,
            "features"   : features,
        }

        date_str  = datetime.date.today().isoformat()
        log_path  = os.path.join(self.ALERTS_DIR, f"{date_str}.jsonl")

        with open(log_path, "a") as f:
            f.write(json.dumps(record) + "\n")

        print(f"[AlertHandler] Logged → {log_path}")
