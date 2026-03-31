"""
test_reader.py
--------------
Quick test — verifies your Sysmon reader is working.
Run this BEFORE building anything else.

    python test_reader.py

Expected: you see colored event lines when you open programs,
visit URLs, or save files.

Must run as Administrator.
"""

import queue
import time
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dynamic.sysmon_reader1 import SysmonReader, TRACKED_EVENT_IDS


def test_connection():
    """Test 1: Can we subscribe to the Sysmon log at all?"""
    print("\n[TEST 1] Checking Sysmon log connection...")
    try:
        import win32evtlog
        import win32event
        signal = win32event.CreateEvent(None, False, False, None)
        handle = win32evtlog.EvtSubscribe(
            "Microsoft-Windows-Sysmon/Operational",
            win32evtlog.EvtSubscribeToFutureEvents,
            SignalEvent=signal,
        )
        import win32api
        win32api.CloseHandle(signal)
        print("  ✓ Connected to Sysmon Operational log successfully")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        print()
        print("  Possible fixes:")
        print("  1. Run this script as Administrator")
        print("  2. Verify Sysmon is installed: sc query Sysmon64")
        print("  3. Install Sysmon: sysmon64.exe -accepteula -i sysmonconfig.xml")
        return False


def test_events(duration_seconds=20):
    """Test 2: Do events actually arrive?"""
    print(f"\n[TEST 2] Listening for {duration_seconds} seconds...")
    print("         Open Notepad, a browser, or any program now.\n")

    q = queue.Queue(maxsize=1000)
    reader = SysmonReader(q, verbose=True)
    reader.start()

    deadline = time.time() + duration_seconds
    event_counts = {}

    try:
        while time.time() < deadline:
            remaining = int(deadline - time.time())
            try:
                event = q.get(timeout=1)
                eid = event["event_id"]
                event_counts[eid] = event_counts.get(eid, 0) + 1
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print("\n  Stopped early by user.")

    reader.stop()

    # Summary
    print("\n" + "─" * 50)
    print("  TEST SUMMARY")
    print("─" * 50)
    total = sum(event_counts.values())

    if total == 0:
        print("  ✗ No events captured!")
        print("  Did you open any programs during the test?")
        print("  Check: sc query Sysmon64 (should show RUNNING)")
    else:
        print(f"  ✓ Captured {total} events in {duration_seconds}s\n")
        for eid, count in sorted(event_counts.items()):
            name = TRACKED_EVENT_IDS.get(eid, "Unknown")
            bar  = "█" * min(count, 30)
            print(f"  EID {eid:2d} ({name:<22}) {count:4d}  {bar}")

    print("─" * 50)

    if total > 0:
        print("\n  ✓ Sysmon reader is working correctly!")
        print("  Next step: build agent/feature_builder.py")
    else:
        print("\n  ✗ No events — fix connection before proceeding.")


def test_parse():
    """Test 3: Does the XML parser work on a sample event?"""
    print("\n[TEST 3] Testing XML parser with sample event...")

    sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2024-01-15T14:32:01.445Z"/>
  </System>
  <EventData>
    <Data Name="ProcessId">4821</Data>
    <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
    <Data Name="CommandLine">notepad</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentProcessId">1234</Data>
    <Data Name="User">DESKTOP\\TestUser</Data>
    <Data Name="Hashes">SHA256=AABBCC1122</Data>
  </EventData>
</Event>"""

    from dynamic.sysmon_reader1 import parse_event_xml
    result = parse_event_xml(sample_xml)

    if result is None:
        print("  ✗ Parser returned None — check parse_event_xml()")
        return False

    assert result["event_id"]   == 1,             f"event_id wrong: {result['event_id']}"
    assert result["event_name"] == "ProcessCreate", f"event_name wrong: {result['event_name']}"
    assert result["pid"]        == 4821,           f"pid wrong: {result['pid']}"
    assert result["data"]["Image"] == "C:\\Windows\\System32\\notepad.exe"

    print("  ✓ Parser works correctly")
    print(f"  ✓ event_id   = {result['event_id']}")
    print(f"  ✓ event_name = {result['event_name']}")
    print(f"  ✓ pid        = {result['pid']}")
    print(f"  ✓ Image      = {result['data']['Image']}")
    return True


# ── Run all tests ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  SYSMON READER — TEST SUITE")
    print("=" * 50)

    # Test 3 first (no admin needed)
    test_parse()

    # Test 1 — needs admin
    if not test_connection():
        print("\n  Fix the connection error before running Test 2.")
        sys.exit(1)

    # Test 2 — live events
    test_events(duration_seconds=20)