# feature_builder.py
# Accumulates Sysmon events per PID and builds the feature vector
# that matches the CIC-MalMem-2022 training schema (52 features).
#
# The model was trained on Volatility memory features, not Sysmon events
# directly. We map Sysmon behavioral signals into the feature slots that
# the model is most sensitive to, and zero-fill everything else.
# This is a deliberate approximation — it works because the top-3 features
# (svcscan.shared_process_services, svcscan.kernel_drivers, svcscan.nservices)
# account for ~98% of model importance, and the rest are near-zero importance.

import time
import json
import math
from collections import defaultdict

# ── Load the exact feature list saved during training ────────────────────────
with open("dynamic/DataSet/feature_names.json") as f:
    FEATURE_NAMES = json.load(f)   # list of 52 strings, in the exact order

# Window duration in seconds — score the process every 30s of activity
WINDOW_SECONDS = 30

# Suspicious parent processes that should never spawn children in normal use
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "foxit reader.exe", "mspaint.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
}

# Registry paths associated with persistence
PERSISTENCE_KEYS = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\winlogon",
    "\\userinit",
    "\\currentversion\\policies\\explorer\\run",
    "scheduledtasks",
    "services",
)

# Temp / staging dirs commonly used by droppers
TEMP_PATHS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
              "\\users\\public\\", "\\programdata\\")

# Ports that are almost never used by legitimate software
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 12345}


class EventWindow:
    """
    Collects Sysmon events for one PID over a sliding 30-second window.
    Call .add(event) for each new event, .ready() to check if 30s elapsed,
    and .to_feature_vector() to get a numpy-ready list aligned to FEATURE_NAMES.
    """

    def __init__(self, pid: int):
        self.pid        = pid
        self.start_time = time.time()
        self.events     = []          # raw list of all events in this window

        # ── Counters updated incrementally on each .add() call ───────────────
        # Network / DNS
        self.net_connections      = 0
        self.unique_dst_ips       = set()
        self.suspicious_ports     = 0
        self.dns_queries          = 0
        self.unique_domains       = set()
        self.dga_entropy_sum      = 0.0   # accumulate; divide by dns_queries for avg

        # File
        self.files_written        = 0
        self.temp_writes          = 0
        self.extension_changes    = 0     # filename ends in known doc ext → encrypted ext

        # Registry
        self.registry_events      = 0
        self.persistence_writes   = 0

        # Process / injection
        self.child_procs          = 0
        self.remote_thread_events = 0
        self.injected_system      = 0     # remote thread targeting system process
        self.spawned_from_browser = 0     # child of chrome/edge/firefox

        # Misc
        self.image_path           = ""    # set on first EID 1 event
        self.parent_image         = ""

    # ── Domain entropy (DGA detection) ───────────────────────────────────────
    @staticmethod
    def _domain_entropy(domain: str) -> float:
        """Shannon entropy of a domain name. DGA domains score > 3.5."""
        name = domain.split(".")[0]   # just the leftmost label
        if not name:
            return 0.0
        freq = defaultdict(int)
        for ch in name:
            freq[ch] += 1
        n = len(name)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    # ── Add one Sysmon event ─────────────────────────────────────────────────
    def add(self, ev: dict):
        self.events.append(ev)
        eid  = ev["eid"]
        data = ev["data"]

        if eid == 1:   # ProcessCreate
            img = data.get("Image", "").lower()
            par = data.get("ParentImage", "").lower()
            if not self.image_path:
                self.image_path   = img
                self.parent_image = par
            self.child_procs += 1
            if any(p in par for p in SUSPICIOUS_PARENTS):
                self.spawned_from_browser += 1

        elif eid == 3:   # NetworkConnect
            self.net_connections += 1
            dst_ip   = data.get("DestinationIp", "")
            dst_port = int(data.get("DestinationPort", 0) or 0)
            if dst_ip:
                self.unique_dst_ips.add(dst_ip)
            if dst_port in SUSPICIOUS_PORTS:
                self.suspicious_ports += 1

        elif eid == 8:   # CreateRemoteThread — always suspicious
            self.remote_thread_events += 1
            target = data.get("TargetImage", "").lower()
            # Injecting into core Windows processes is critical
            if any(s in target for s in ("lsass", "svchost", "csrss",
                                          "wininit", "explorer", "services")):
                self.injected_system += 1

        elif eid == 11:   # FileCreate
            self.files_written += 1
            fname = data.get("TargetFilename", "").lower()
            if any(t in fname for t in TEMP_PATHS):
                self.temp_writes += 1
            # Ransomware pattern: replaces known document extensions
            if any(fname.endswith(e) for e in
                   (".locked", ".encrypted", ".enc", ".crypt", ".crypto",
                    ".cerber", ".locky", ".zepto", ".wnry", ".wncry")):
                self.extension_changes += 1

        elif eid in (12, 13):   # Registry key or value
            self.registry_events += 1
            target = data.get("TargetObject", "").lower()
            if any(k in target for k in PERSISTENCE_KEYS):
                self.persistence_writes += 1

        elif eid == 22:   # DnsQuery
            self.dns_queries += 1
            domain = data.get("QueryName", "")
            if domain:
                self.unique_domains.add(domain.lower())
                self.dga_entropy_sum += self._domain_entropy(domain)

    # ── Has 30 seconds passed? ───────────────────────────────────────────────
    def ready(self) -> bool:
        return (time.time() - self.start_time) >= WINDOW_SECONDS

    def reset_timer(self):
        """Call after scoring to start a fresh window (keep counters)."""
        self.start_time = time.time()

    # ── Build the feature vector ─────────────────────────────────────────────
    def to_feature_vector(self) -> list:
        """
        Returns a list of floats aligned to FEATURE_NAMES (52 features).
        We set the high-importance svcscan features based on behavioral signals,
        and zero-fill low-importance Volatility-specific slots.
        """
        # Derived values
        n_net    = self.net_connections
        n_dns    = max(self.dns_queries, 1)   # avoid div-by-zero
        avg_dga  = self.dga_entropy_sum / n_dns
        n_unique_ip = len(self.unique_dst_ips)
        n_unique_dom = len(self.unique_domains)

        # ── Map behavioral signals into the model's feature space ─────────────
        #
        # svcscan.shared_process_services (importance 0.49):
        #   In memory forensics this counts shared-process Windows services.
        #   Malware drives this high via injection or service installation.
        #   We proxy it using: remote threads + persistence writes + suspicious ports.
        svcscan_shared = (
            self.remote_thread_events * 3
            + self.injected_system * 5
            + self.persistence_writes * 2
            + self.suspicious_ports
        )

        # svcscan.kernel_drivers (importance 0.29):
        #   Rootkits load kernel drivers. Proxy: injected_system is the
        #   strongest Sysmon signal for kernel-level activity.
        svcscan_kernel = self.injected_system * 2 + self.remote_thread_events

        # svcscan.nservices (importance 0.21):
        #   Total services visible. Malware installs new services.
        #   Proxy: persistence_writes to Services registry key.
        svcscan_nservices = max(10, self.persistence_writes * 3)

        # Build a lookup dict for all 52 features, defaulting to 0
        vec = {name: 0.0 for name in FEATURE_NAMES}

        # ── High-importance features (account for ~98% of model weight) ───────
        vec["svcscan.shared_process_services"] = float(svcscan_shared)
        vec["svcscan.kernel_drivers"]           = float(svcscan_kernel)
        vec["svcscan.nservices"]                = float(svcscan_nservices)
        vec["svcscan.process_services"]         = float(self.child_procs)
        vec["svcscan.nactive"]                  = float(svcscan_nservices)

        # ── Medium-importance features ─────────────────────────────────────────
        vec["malfind.commitCharge"]             = float(self.remote_thread_events)
        vec["malfind.ninjections"]              = float(self.remote_thread_events)
        vec["malfind.uniqueInjections"]         = float(self.injected_system)
        vec["malfind.protection"]               = float(self.injected_system)

        vec["psxview.not_in_deskthrd"]          = float(min(self.injected_system, 1))
        vec["psxview.not_in_ethread_pool_false_avg"] = float(
            self.remote_thread_events / max(self.child_procs, 1)
        )
        vec["psxview.not_in_deskthrd_false_avg"] = float(
            self.injected_system / max(self.child_procs, 1)
        )

        vec["callbacks.ncallbacks"]             = float(self.persistence_writes)
        vec["callbacks.nanonymous"]             = float(self.persistence_writes)

        vec["handles.avg_handles_per_proc"]     = float(n_net + self.registry_events)
        vec["handles.nhandles"]                 = float(
            self.files_written + n_net + self.registry_events
        )
        vec["handles.nevent"]                   = float(self.registry_events)
        vec["handles.nfile"]                    = float(self.files_written)
        vec["handles.nkey"]                     = float(self.registry_events)
        vec["handles.ndirectory"]               = float(self.temp_writes)
        vec["handles.nmutant"]                  = float(self.remote_thread_events)
        vec["handles.nsemaphore"]               = float(self.child_procs)
        vec["handles.ndesktop"]                 = float(self.spawned_from_browser)

        vec["ldrmodules.not_in_load_avg"]       = float(
            self.remote_thread_events / max(self.child_procs, 1)
        )
        vec["ldrmodules.not_in_init_avg"]       = float(
            self.injected_system / max(self.child_procs, 1)
        )
        vec["ldrmodules.not_in_mem_avg"]        = float(
            self.remote_thread_events / max(self.child_procs, 1)
        )
        vec["ldrmodules.not_in_load"]           = float(self.remote_thread_events)
        vec["ldrmodules.not_in_init"]           = float(self.injected_system)
        vec["ldrmodules.not_in_mem"]            = float(self.remote_thread_events)

        vec["pslist.nproc"]                     = float(self.child_procs)
        vec["pslist.avg_threads"]               = float(n_net + self.child_procs)
        vec["pslist.avg_handlers"]              = float(self.registry_events)
        vec["pslist.nppid"]                     = float(self.spawned_from_browser)

        vec["dlllist.ndlls"]                    = float(self.child_procs * 3)
        vec["dlllist.avg_dlls_per_proc"]        = float(3.0)  # benign baseline

        vec["modules.nmodules"]                 = float(self.child_procs + svcscan_kernel)

        # ── Return as ordered list matching FEATURE_NAMES exactly ─────────────
        return [vec[name] for name in FEATURE_NAMES]