#!/usr/bin/env python3
"""Batch scan with resume and incremental saving."""
import os
import sys
import json
import time
import requests

APK_DIR = sys.argv[1] if len(sys.argv) > 1 else "/home/madhu/KrackHack/apks"
API_URL = "http://localhost:8000/api/scan"
RESULTS_FILE = "/home/madhu/KrackHack/DroidSec/backend/batch_results.json"

# Load existing results if any
results = []
processed_names = set()
if os.path.exists(RESULTS_FILE):
    try:
        with open(RESULTS_FILE, "r") as f:
            results = json.load(f)
            processed_names = {r.get("name") for r in results}
            print(f"Loaded {len(results)} existing results.")
    except Exception as e:
        print(f"Error loading {RESULTS_FILE}: {e}")

apks = sorted([f for f in os.listdir(APK_DIR) if f.endswith(".apk")])
print(f"Found {len(apks)} APKs in {APK_DIR}. Need to scan: {len(apks) - len(processed_names)}\n")

for i, apk_name in enumerate(apks, 1):
    if apk_name in processed_names:
        print(f"[{i}/{len(apks)}] Skipping {apk_name} (already scanned)", flush=True)
        continue

    apk_path = os.path.join(APK_DIR, apk_name)
    size_mb = os.path.getsize(apk_path) / (1024 * 1024)
    print(f"[{i}/{len(apks)}] Scanning: {apk_name} ({size_mb:.1f} MB)...", flush=True)
    
    t0 = time.time()
    try:
        with open(apk_path, "rb") as f:
            resp = requests.post(
                API_URL,
                files={"file": (apk_name, f, "application/vnd.android.package-archive")},
                timeout=1800
            )
        elapsed = time.time() - t0
        
        result_entry = {}
        if resp.status_code == 200:
            data = resp.json()
            score_data = data.get("security_score", {})
            sev = data.get("severity_breakdown", {})
            total = data.get("total_findings", 0)
            displayed = data.get("unique_findings", len(data.get("findings", [])))

            result_entry = {
                "name": apk_name,
                "size_mb": round(size_mb, 1),
                "score": score_data.get("score", "?"),
                "grade": score_data.get("grade", "?"),
                "total_findings": total,
                "displayed": displayed,
                "critical": sev.get("critical", 0),
                "high": sev.get("high", 0),
                "medium": sev.get("medium", 0),
                "info": sev.get("info", 0),
                "elapsed_s": round(elapsed, 1),
                "package": data.get("package", "?"),
            }
            print(f"  ✓ Score: {result_entry['score']}/100 ({result_entry['grade']}) | {total} raw → {displayed} displayed | {elapsed:.0f}s", flush=True)
        else:
            err = resp.text[:200]
            result_entry = {"name": apk_name, "error": f"HTTP {resp.status_code}: {err}", "elapsed_s": round(elapsed, 1)}
            print(f"  ✗ FAILED (HTTP {resp.status_code}): {err[:100]}", flush=True)

        results.append(result_entry)
        
        # Incremental save
        with open(RESULTS_FILE, "w") as f:
            json.dump(results, f, indent=2)

    except Exception as e:
        elapsed = time.time() - t0
        print(f"  ✗ ERROR: {e}", flush=True)
        # Don't save transient errors, retry later? Or save as failed? Let's skip saving fatal errors to retry manually.
        # Actually save error so we know it failed
        results.append({"name": apk_name, "error": str(e), "elapsed_s": round(elapsed, 1)})
        with open(RESULTS_FILE, "w") as f:
            json.dump(results, f, indent=2)

print(f"\nAll done! Results saved to {RESULTS_FILE}")
