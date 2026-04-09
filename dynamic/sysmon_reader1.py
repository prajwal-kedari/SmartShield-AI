"""
sysmon_reader.py
Polls Sysmon log every 500ms using EvtQuery + XPath bookmark.
More reliable than signal-based EvtSubscribe across Windows versions.
Must run as Administrator.
"""

import win32evtlog
import win32api
import xml.etree.ElementTree as ET
import queue
import threading
import time
import json
import os

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

TRACKED_EVENT_IDS = {
    1:  "ProcessCreate",
    3:  "NetworkConnect",
    8:  "CreateRemoteThread",
    11: "FileCreate",
    12: "RegistryCreateKey",
    13: "RegistrySetValue",
    22: "DnsQuery",
}

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def parse_event_xml(xml_string: str) -> dict | None:
    try:
        root = ET.fromstring(xml_string)
        event_id_el = root.find(f".//{{{NS}}}EventID")
        if event_id_el is None:
            return None
        event_id = int(event_id_el.text)
        if event_id not in TRACKED_EVENT_IDS:
            return None
        time_el = root.find(f".//{{{NS}}}TimeCreated")
        timestamp = time_el.get("SystemTime", "") if time_el is not None else ""
        data = {}
        for d in root.findall(f".//{{{NS}}}Data"):
            name = d.get("Name", "")
            value = d.text or ""
            if name:
                data[name] = value
        try:
            pid = int(data.get("ProcessId", "0"))
        except ValueError:
            pid = 0
        return {
            "event_id":   event_id,
            "event_name": TRACKED_EVENT_IDS[event_id],
            "timestamp":  timestamp,
            "pid":        pid,
            "data":       data,
        }
    except Exception as e:
        return None


def extract_record_id(xml_string: str) -> int | None:
    try:
        root = ET.fromstring(xml_string)
        el = root.find(f".//{{{NS}}}EventRecordID")
        if el is not None and el.text:
            return int(el.text)
    except Exception:
        pass
    return None


class SysmonReader:
    def __init__(self, output_queue: queue.Queue, verbose: bool = False):
        self.queue   = output_queue
        self.verbose = verbose
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, name="SysmonReader", daemon=True)

    def start(self):
        print(f"[SysmonReader] Starting — listening on: {SYSMON_CHANNEL}")
        self._thread.start()

    def stop(self):
        print("[SysmonReader] Stopping...")
        self._stop.set()
        self._thread.join(timeout=5)

    def _get_latest_record_id(self) -> int:
        try:
            qh = win32evtlog.EvtQuery(
                SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                "*",
            )
            handles = win32evtlog.EvtNext(qh, 1, Timeout=1000)
            if handles:
                xml_str = win32evtlog.EvtRender(handles[0], win32evtlog.EvtRenderEventXml)
                try: win32api.CloseHandle(handles[0])
                except: pass
                try: win32api.CloseHandle(qh)
                except: pass
                rid = extract_record_id(xml_str)
                print(f"[SysmonReader] Bookmark set at RecordID: {rid}")
                return rid or 0
            try: win32api.CloseHandle(qh)
            except: pass
        except Exception as e:
            print(f"[SysmonReader] Could not get latest record ID: {e}")
        return 0

    def _run(self):
        # Verify connection first
        try:
            test = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath, "*")
            try: win32api.CloseHandle(test)
            except: pass
        except Exception as e:
            print(f"[SysmonReader] ERROR: Cannot access Sysmon log.")
            print(f"  Reason : {e}")
            print(f"  Fix    : Run as Administrator.")
            print(f"  Fix    : sc query Sysmon64  (must show RUNNING)")
            return

        last_record_id = self._get_latest_record_id()
        print(f"[SysmonReader] Subscribed. Polling for RecordID > {last_record_id} ...")
        stats = {"total": 0, "by_id": {}}

        while not self._stop.is_set():
            time.sleep(0.5)
            xpath = f"*[System[EventRecordID > {last_record_id}]]"
            try:
                qh = win32evtlog.EvtQuery(
                    SYSMON_CHANNEL,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                    xpath,
                )
            except Exception as e:
                print(f"[SysmonReader] Query error: {e}")
                continue

            while not self._stop.is_set():
                try:
                    handles = win32evtlog.EvtNext(qh, 50, Timeout=0)
                except Exception:
                    break
                if not handles:
                    break
                for handle in handles:
                    try:
                        xml_str = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                        rid = extract_record_id(xml_str)
                        if rid and rid > last_record_id:
                            last_record_id = rid
                        try: win32api.CloseHandle(handle)
                        except: pass
                        event = parse_event_xml(xml_str)
                        if event is None:
                            continue
                        try:
                            self.queue.put_nowait(event)
                        except queue.Full:
                            print("[SysmonReader] WARNING: queue full, dropping event")
                        stats["total"] += 1
                        eid = event["event_id"]
                        stats["by_id"][eid] = stats["by_id"].get(eid, 0) + 1
                        if self.verbose:
                            _pretty_print(event)
                    except Exception as e:
                        print(f"[SysmonReader] Handle error: {e}")
            try: win32api.CloseHandle(qh)
            except: pass

        print(f"[SysmonReader] Stopped. Stats: {stats}")


def _pretty_print(event: dict):
    colors = {1:"\033[92m", 3:"\033[94m", 8:"\033[91m",
              11:"\033[93m", 12:"\033[95m", 13:"\033[95m", 22:"\033[96m"}
    reset = "\033[0m"
    color = colors.get(event["event_id"], "")
    eid   = event["event_id"]
    ename = event["event_name"]
    pid   = event["pid"]
    ts    = event["timestamp"][:19].replace("T", " ") if event["timestamp"] else "?"
    d     = event["data"]
    detail = {
        1:  d.get("Image","?") + "  ←  " + d.get("ParentImage","?"),
        3:  d.get("Image","?") + "  →  " + d.get("DestinationIp","?") + ":" + d.get("DestinationPort","?"),
        8:  "!! INJECT: " + d.get("SourceImage","?") + "  →  " + d.get("TargetImage","?"),
        11: d.get("Image","?") + "  wrote  " + d.get("TargetFilename","?"),
        12: d.get("Image","?") + "  regkey  " + d.get("TargetObject","?"),
        13: d.get("Image","?") + "  regset  " + d.get("TargetObject","?"),
        22: d.get("Image","?") + "  dns  " + d.get("QueryName","?"),
    }.get(eid, str(d)[:100])
    if (eid == 22 ):
        print(f"{color}[{ts}] 111 EID={eid:2d} ({ename:<22}) PID={pid:<6} {detail}{reset}")


if __name__ == "__main__":
    print("=" * 65)
    print("  Sysmon Reader — Live Event Monitor (polling mode)")
    print("  Tracking:", list(TRACKED_EVENT_IDS.keys()))
    print("  Press Ctrl+C to stop")
    print("=" * 65)
    print()
    print("  Open Notepad, browser, save a file — watch events appear")
    print()

    event_queue = queue.Queue(maxsize=5000)
    reader = SysmonReader(event_queue, verbose=True)
    reader.start()

    try:
        count = 0
        while True:
            time.sleep(5)
            count += 1
            print(f"\n  [{count*5}s] Total events so far: {event_queue.qsize()}\n")
    except KeyboardInterrupt:
        print("\n[Main] Stopping...")
        reader.stop()
        events = []
        while not event_queue.empty():
            events.append(event_queue.get_nowait())
        if events:
            os.makedirs("data/logs", exist_ok=True)
            with open("data/logs/sample_events.json", "w") as f:
                json.dump(events[-10:], f, indent=2, default=str)
            print(f"[Main] Saved last {min(10,len(events))} events → data/logs/sample_events.json")
        else:
            print("[Main] No events captured.")