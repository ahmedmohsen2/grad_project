"""
E2E Pipeline Test — verifies the full scan execution chain:
  insert → thread pool → orchestrator → progress callbacks → DB → API results
"""
import logging, sys, io, json, uuid, asyncio, time
logging.basicConfig(level=logging.WARNING)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from db import sync_init_pool, sync_get_pentest_scan
sync_init_pool(retries=1)

import api  # boots Flask + thread pool

print("=== E2E PIPELINE TEST ===")
print("Target: 127.0.0.1  Type: quick")
print()

# Fire the scan via the internal helper (same path as POST /pentest/scan)
from api import _queue_pentest_scan
scan_id = uuid.uuid4().hex[:12]

ok = _queue_pentest_scan(scan_id, "127.0.0.1", "quick", "e2e_test")
print(f"Scheduled: scan_id={scan_id}  ok={ok}")
print()

# Poll the DB every 2 seconds for up to 90 seconds
print(f"{'Time':>5}  {'Status':10}  {'Progress':>8}  Stage")
print("-" * 45)
deadline = time.time() + 90
last_progress = -1
while time.time() < deadline:
    row = sync_get_pentest_scan(scan_id)
    if not row:
        print("  scan record not found!")
        break
    status = row.get("status", "?")
    progress = row.get("progress", 0)
    stage = row.get("current_stage", "?")
    elapsed = int(time.time() - (deadline - 90))
    if progress != last_progress:
        print(f"{elapsed:>5}s  {status:10}  {progress:>7}%  {stage}")
        last_progress = progress
    if status in ("completed", "failed"):
        break
    time.sleep(2)

print()
print("=== FINAL STATE ===")
row = sync_get_pentest_scan(scan_id)
if row:
    print(f"status:        {row.get('status')}")
    print(f"progress:      {row.get('progress')}%")
    print(f"current_stage: {row.get('current_stage')}")
    results = row.get("results") or {}
    if isinstance(results, dict):
        print(f"result keys:   {list(results.keys())}")
        vulns = results.get("vulnerabilities", [])
        ports = results.get("scanner", {}).get("open_ports", []) if isinstance(results.get("scanner"), dict) else []
        print(f"open ports:    {len(ports)}")
        print(f"vulns found:   {len(vulns)}")
        report = results.get("report") or {}
        if report:
            print(f"risk score:    {report.get('risk_score', 'N/A')}")
    print(f"completed_at:  {row.get('completed_at')}")

print()
print("=== API ENDPOINT CHECK ===")
with api.app.test_client() as c:
    r = c.get(f"/pentest/results/{scan_id}")
    d = r.get_json() or {}
    print(f"HTTP {r.status_code}")
    print(f"status={d.get('status')}  progress={d.get('progress')}  stage={d.get('current_stage')}")
    res = d.get("results") or {}
    print(f"results keys: {list(res.keys()) if isinstance(res, dict) else res}")
