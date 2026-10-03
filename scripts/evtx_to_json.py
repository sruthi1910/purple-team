#!/usr/bin/env python3
"""Convert EVTX files to one-JSON-object-per-line files for Splunk.

Usage: python3 scripts/evtx_to_json.py <evtx_dir> <out_dir>
Requires: pip install evtx
"""
import glob, json, os, sys
from evtx import PyEvtxParser

def flatten(section, row):
    """Copy scalar fields from EventData or UserData into row."""
    if not isinstance(section, dict):
        return
    for k, v in section.items():
        if k == "#attributes":
            continue
        if isinstance(v, dict):          # UserData wraps fields in one child element
            flatten(v, row)
        elif not isinstance(v, list):
            row[k] = v

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
for path in sorted(glob.glob(os.path.join(src, "*.evtx"))):
    name = os.path.basename(path)
    n = 0
    with open(os.path.join(out, name.replace(".evtx", ".json")), "w") as f:
        for rec in PyEvtxParser(path).records_json():
            ev = json.loads(rec["data"]).get("Event", {})
            sysd = ev.get("System", {}) or {}
            eid = sysd.get("EventID")
            if isinstance(eid, dict):
                eid = eid.get("#text")
            created = (sysd.get("TimeCreated") or {}).get("#attributes", {}).get("SystemTime")
            row = {"timestamp": created or rec["timestamp"], "EventCode": eid,
                   "Channel": sysd.get("Channel"), "Computer": sysd.get("Computer"),
                   "source_file": name}
            flatten(ev.get("EventData"), row)
            flatten(ev.get("UserData"), row)
            f.write(json.dumps(row) + "\n")
            n += 1
    print(f"{name}: {n} events")
