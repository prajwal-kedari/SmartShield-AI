# process_monitor.py
# Main runtime loop.  Run as Administrator.
#
# Usage:
#   python process_monitor.py
#
# Ctrl+C to stop cleanly.

import queue
import time
import signal
import sys
import json
import joblib
import numpy as np
from collections import defaultdict

from SysMon_reader   import SysmonReader
from feature_builder import EventWindow, FEATURE_NAMES
from alert  import AlertHandler

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_PATH   = "dynamic/Model/smartshield_Dynamic.pkl"
META_PATH    = "dynamic/DataSet/model_meta.json"

# Probability thresholds (from model_meta.json)
THRESH_BLOCK     = 0.55   # ≥ this → kill PID + alert
THRESH_WATCHLIST = 0.35   # ≥ this → log + keep watching

# PIDs we never score (system processes — false-positive magnets)
EXEMPT_PIDS = {0, 4}      # System Idle + System

# How many events can queue up before we start dropping (backpressure)
QUEUE_MAXSIZE = 2000

# ── Static PE model (Gate 1) ──────────────────────────────────────────────────
# If you have your existing static model, load it here.
# Otherwise set STATIC_MODEL = None to skip Gate 1.
STATIC_MODEL_PATH = "static/model.pkl"          # adjust if needed
STATIC_FEATURES   = "static/feature_names.json"


def _load_static():
    try:
        m  = joblib.load(STATIC_MODEL_PATH)
        fn = json.load(open(STATIC_FEATURES))
        print(f"[Monitor] Static PE model loaded ({len(fn)} features)")
        return m, fn
    except Exception as e:
        print(f"[Monitor] Static model not found ({e}) — Gate 1 disabled")
        return None, []


def _static_score(model, feature_names: list, exe_path: str) -> float:
    """
    Extract PE features from exe_path and return malware probability.
    Returns 0.0 if pefile is unavailable or the file can't be parsed.
    """
    try:
        import pefile
        import numpy as np
        pe   = pefile.PE(exe_path, fast_load=True)
        oh   = pe.OPTIONAL_HEADER
        fh   = pe.FILE_HEADER

        raw = {
            "MajorLinkerVersion":           oh.MajorLinkerVersion,
            "MinorOperatingSystemVersion":  oh.MinorOperatingSystemVersion,
            "MajorSubsystemVersion":        oh.MajorSubsystemVersion,
            "SizeOfStackReserve":           oh.SizeOfStackReserve,
            "TimeDateStamp":                fh.TimeDateStamp,
            "MajorOperatingSystemVersion":  oh.MajorOperatingSystemVersion,
            "Characteristics":              fh.Characteristics,
            "ImageBase":                    oh.ImageBase,
            "Subsystem":                    oh.Subsystem,
            "MinorImageVersion":            oh.MinorImageVersion,
            "MinorSubsystemVersion":        oh.MinorSubsystemVersion,
            "SizeOfInitializedData":        oh.SizeOfInitializedData,
            "DllCharacteristics":           oh.DllCharacteristics,
            "MajorImageVersion":            oh.MajorImageVersion,
            "AddressOfEntryPoint":          oh.AddressOfEntryPoint,
            "SizeOfHeaders":                oh.SizeOfHeaders,
            "CheckSum":                     oh.CheckSum,
        }

        # Section stats
        entropies = [s.get_entropy() for s in pe.sections]
        vsizes    = [s.Misc_VirtualSize for s in pe.sections]
        raw["SectionMinEntropy"]      = min(entropies) if entropies else 0
        raw["SectionMinVirtualsize"]  = min(vsizes)    if vsizes    else 0
        raw["SectionMaxChar"]         = max(
            (s.Characteristics for s in pe.sections), default=0
        )

        # Import / export directory sizes
        try:
            raw["DirectoryEntryImportSize"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        except Exception:
            raw["DirectoryEntryImportSize"] = 0
        try:
            raw["DirectoryEntryExport"]      = 1
            raw["ImageDirectoryEntryExport"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except Exception:
            raw["DirectoryEntryExport"]      = 0
            raw["ImageDirectoryEntryExport"] = 0

        vec = np.array([[raw.get(f, 0) for f in feature_names]], dtype=float)
        return float(model.predict_proba(vec)[0][1])

    except Exception:
        return 0.0   # can't parse → don't block


# ─────────────────────────────────────────────────────────────────────────────

class ProcessMonitor:

    def __init__(self):
        # Load behavioral model
        self.model = joblib.load(MODEL_PATH)
        meta       = json.load(open(META_PATH))
        print(f"[Monitor] Behavioral model loaded — "
              f"best_iter={meta['best_iteration']}  "
              f"test_auc={meta['test_auc']:.4f}")

        # Load static model (optional)
        self.static_model, self.static_features = _load_static()

        # Alert handler
        self.alerts = AlertHandler()

        # Sysmon reader → queue
        self.q      = queue.Queue(maxsize=QUEUE_MAXSIZE)
        self.reader = SysmonReader(self.q)

        # Per-PID event windows
        self.windows: dict[int, EventWindow] = defaultdict(lambda: None)

        # PIDs we've already flagged — don't re-score them
        self.flagged: set[int] = set()

        self._running = True

    # ── Gate 1: static PE scan on first ProcessCreate ────────────────────────
    def _gate1(self, pid: int, exe_path: str) -> bool:
        """Returns True if the static model says this file is malware."""
        if self.static_model is None or not exe_path:
            return False
        prob = _static_score(self.static_model, self.static_features, exe_path)
        if prob >= THRESH_BLOCK:
            self.alerts.fire(
                pid      = pid,
                exe_path = exe_path,
                prob     = prob,
                gate     = "static_pe",
                features = {},
            )
            self.flagged.add(pid)
            return True
        return False

    # ── Gate 2: behavioral score after 30s window ────────────────────────────
    def _gate2(self, pid: int, window: EventWindow):
        vec  = window.to_feature_vector()
        prob = float(self.model.predict_proba([vec])[0][1])

        if prob >= THRESH_BLOCK:
            # Build a readable dict of non-zero features for the alert
            top = {
                FEATURE_NAMES[i]: round(v, 3)
                for i, v in enumerate(vec)
                if v != 0.0
            }
            self.alerts.fire(
                pid      = pid,
                exe_path = window.image_path,
                prob     = prob,
                gate     = "behavioral",
                features = top,
            )
            self.flagged.add(pid)

        elif prob >= THRESH_WATCHLIST:
            print(f"[WATCHLIST] PID {pid:<6} {window.image_path}  "
                  f"p={prob:.3f}  — monitoring continues")

        else:
            pass   # clean; no output to avoid log spam

        window.reset_timer()   # slide the window forward

    # ── Main loop ─────────────────────────────────────────────────────────────
    def run(self):
        self.reader.start()
        print("[Monitor] Running — press Ctrl+C to stop\n")

        try:
            while self._running:
                # Drain up to 100 events per iteration to stay responsive
                for _ in range(100):
                    try:
                        ev = self.q.get_nowait()
                    except queue.Empty:
                        break

                    pid = ev["pid"]

                    if pid in EXEMPT_PIDS or pid in self.flagged:
                        continue

                    # First time we see this PID → create a window
                    if self.windows[pid] is None:
                        self.windows[pid] = EventWindow(pid)

                        # Gate 1: static scan on process launch
                        if ev["eid"] == 1:
                            exe = ev["data"].get("Image", "")
                            if self._gate1(pid, exe):
                                continue   # already handled

                    # Feed event into the window
                    self.windows[pid].add(ev)

                    # Gate 2: score when window is ready
                    if self.windows[pid].ready():
                        self._gate2(pid, self.windows[pid])

                # Small sleep to avoid busy-waiting when queue is empty
                time.sleep(0.05)

        except KeyboardInterrupt:
            print("\n[Monitor] Shutting down...")
        finally:
            self.reader.stop()
            print("[Monitor] Done.")

    def stop(self):
        self._running = False


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    monitor = ProcessMonitor()

    # Clean Ctrl+C handling
    def _sigint(sig, frame):
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)
    monitor.run()