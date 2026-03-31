# sysmon_reader.py
# Reads live events from Sysmon and puts them in a queue.
# Must run as Administrator.

import win32evtlog, win32api
import xml.etree.ElementTree as ET
import queue, threading, time

# ── What channel to read from ─────────────────────────────────────────────────
CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# ── XML namespace used in every Sysmon event ─────────────────────────────────
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# ── The 6 event types we care about (ignore everything else) ─────────────────
EVENTS = {
    1:  "ProcessCreate",       # a new program was launched
    3:  "NetworkConnect",      # a program made a network connection
    8:  "CreateRemoteThread",  # a program injected into another (very suspicious)
    11: "FileCreate",          # a file was written to disk
    12: "RegistryCreateKey",   # a registry key was created
    13: "RegistrySetValue",    # a registry value was changed
    22: "DnsQuery",            # a DNS lookup was made
}


def _get_start_id() -> int:
    """
    Get the RecordID of the latest existing event.
    We start from here so we only see NEW events, not old history.
    """
    try:
        # Query in reverse so first result = most recent event
        qh = win32evtlog.EvtQuery(
            CHANNEL,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            "*"
        )
        handles = win32evtlog.EvtNext(qh, 1, Timeout=1000)
        if handles:
            xml  = win32evtlog.EvtRender(handles[0], win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml)
            el   = root.find(f".//{{{NS}}}EventRecordID")
            return int(el.text) if el is not None else 0
    except:
        pass
    return 0


def _parse(xml_str: str) -> dict | None:
    """
    Turn raw XML string into a clean Python dict.
    Returns None if it's an event type we don't track.

    Output looks like:
    {
        "eid":  1,
        "name": "ProcessCreate",
        "pid":  4821,
        "data": { "Image": "C:\\notepad.exe", "ParentImage": "...", ... }
    }
    """
    try:
        root = ET.fromstring(xml_str)

        # Get event ID number
        eid = int(root.find(f".//{{{NS}}}EventID").text)

        # Skip events we don't care about
        if eid not in EVENTS:
            return None

        # Collect all <Data Name="...">value</Data> fields into a dict
        data = {
            d.get("Name"): d.text or ""
            for d in root.findall(f".//{{{NS}}}Data")
            if d.get("Name")
        }

        # Skip reverse DNS lookups (end with .arpa) — only want real domains like google.com
        if eid == 22 and data.get("QueryName", "").endswith(".arpa"):
            return None

        return {
            "eid":  eid,
            "name": EVENTS[eid],
            "pid":  int(data.get("ProcessId", 0) or 0),
            "data": data,
        }
    except:
        return None


class SysmonReader:
    """
    Polls the Sysmon log every 500ms.
    Any new events get parsed and dropped into output_queue.

    Usage:
        q = queue.Queue()
        r = SysmonReader(q)
        r.start()
        event = q.get()   # blocks until something arrives
        r.stop()
    """

    def __init__(self, output_queue: queue.Queue):
        self.q       = output_queue
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        print("[SysmonReader] Started")

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)
        print("[SysmonReader] Stopped")

    def _run(self):
        # Remember where we left off so we never re-read old events
        last_id = _get_start_id()
        print(f"[SysmonReader] Listening from RecordID > {last_id}")

        while not self._stop.is_set():
            time.sleep(0.5)  # poll every 500ms

            # Ask Sysmon for any events newer than last_id
            try:
                qh = win32evtlog.EvtQuery(
                    CHANNEL,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                    f"*[System[EventRecordID > {last_id}]]"
                )
            except:
                continue

            # Drain all results in batches of 50
            while not self._stop.is_set():
                try:    handles = win32evtlog.EvtNext(qh, 50, Timeout=0)
                except: break
                if not handles: break

                for h in handles:
                    try:
                        xml = win32evtlog.EvtRender(h, win32evtlog.EvtRenderEventXml)

                        # Advance our bookmark to this event's RecordID
                        root = ET.fromstring(xml)
                        el   = root.find(f".//{{{NS}}}EventRecordID")
                        if el is not None and el.text:
                            last_id = max(last_id, int(el.text))

                        try: win32api.CloseHandle(h)
                        except: pass

                        # Parse and push to queue
                        ev = _parse(xml)
                        if ev:
                            try:    self.q.put_nowait(ev)
                            except queue.Full: pass  # drop if queue is full

                    except: pass

            try: win32api.CloseHandle(qh)
            except: pass


# ── Quick test — run this file directly ──────────────────────────────────────
if __name__ == "__main__":
    print("Listening for Sysmon events — open Notepad, a browser, save a file...")
    print("Ctrl+C to stop\n")

    q = queue.Queue()
    r = SysmonReader(q)
    r.start()

    # Color codes for each event type
    COLORS = {1:"\033[92m", 3:"\033[94m", 8:"\033[91m",
              11:"\033[93m", 12:"\033[95m", 13:"\033[95m", 22:"\033[96m"}
    RESET  = "\033[0m"

    try:
        while True:
            ev   = q.get()           # wait for next event
            d    = ev["data"]
            # col  = COLORS.get(ev["eid"], "")

            # Pick the most useful field to print per event type
            detail = {
                1:  d.get("Image","?") + " <- " + d.get("ParentImage","?"),
                3:  d.get("Image","?") + " -> " + d.get("DestinationIp","?") + ":" + d.get("DestinationPort","?"),
                8:  "!! INJECT: " + d.get("SourceImage","?") + " -> " + d.get("TargetImage","?"),
                11: d.get("Image","?") + " wrote " + d.get("TargetFilename","?"),
                12: d.get("Image","?") + " -> " + d.get("TargetObject","?"),
                13: d.get("Image","?") + " -> " + d.get("TargetObject","?"),
                22: d.get("Image","?") + " dns " + d.get("QueryName","?"),
            }.get(ev["eid"], str(d)[:80])

            # if ev["eid"]==22:
            print(f"EID={ev['eid']} ({ev['name']:<22}) PID={ev['pid']:<6} {detail}{RESET}")

    except KeyboardInterrupt:
        r.stop() 