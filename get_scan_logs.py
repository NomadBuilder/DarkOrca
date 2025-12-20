#!/usr/bin/env python3
"""Quick script to get logs for a running scan from the backend."""

import sys
import requests
import json
from datetime import datetime

if len(sys.argv) < 2:
    print("Usage: python3 get_scan_logs.py <scan_id>")
    print("Example: python3 get_scan_logs.py scan_20251219_224318")
    sys.exit(1)

scan_id = sys.argv[1]
base_url = "http://localhost:5001"

print(f"Fetching status for scan: {scan_id}")
print("=" * 60)

try:
    # Get scan status
    response = requests.get(f"{base_url}/api/scan/{scan_id}/status", timeout=5)
    if response.status_code == 200:
        status = response.json()
        print("\n📊 Scan Status:")
        print(json.dumps(status, indent=2))
        
        # Calculate elapsed time
        if status.get('started_at'):
            try:
                started = datetime.fromisoformat(status['started_at'].replace('Z', '+00:00'))
                elapsed = datetime.now(started.tzinfo) - started
                print(f"\n⏱️  Elapsed Time: {elapsed}")
            except:
                pass
    else:
        print(f"❌ Failed to get status: {response.status_code}")
        print(response.text)
        
except requests.exceptions.ConnectionError:
    print(f"❌ Cannot connect to {base_url}")
    print("Make sure the web app is running!")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "=" * 60)
print("💡 Note: For detailed backend logs, check the terminal where web_app.py is running")
print("   The logs are written to stdout/stderr of the Flask process")
