#!/usr/bin/env python3
import requests
import time
import sys
import os

if len(sys.argv) != 3:
    print("Usage: python zap_scan.py http://localhost:5000/test_mode your_api_key")
    sys.exit(1)

target = sys.argv[1]
api_key = sys.argv[2]
base_url = "http://localhost:8080"            # <- base, no /JSON here
headers = {"X-ZAP-API-Key": api_key}

print(f"Starting ZAP scan on {target}...")

# Start spider (JSON)
print("Starting spider...")
resp = requests.get(f"{base_url}/JSON/spider/action/scan/", params={"url": target, "apikey": api_key}, headers=headers)
resp.raise_for_status()
spider_id = resp.json().get("scan")
print("Spider ID:", spider_id)

# Wait for spider
while True:
    status_resp = requests.get(f"{base_url}/JSON/spider/view/status/", params={"scanId": spider_id, "apikey": api_key}, headers=headers)
    status = status_resp.json().get("status", "0")
    if int(status) == 100:
        break
    print(f"Spider progress: {status}%")
    time.sleep(2)
print("Crawl complete.")

# Start active scan (JSON)
print("Starting active scan...")
resp = requests.get(f"{base_url}/JSON/ascan/action/scan/", params={"url": target, "recurse": "true", "inScopeOnly": "false", "apikey": api_key}, headers=headers)
resp.raise_for_status()
scan_id = resp.json().get("scan")
print("Active scan ID:", scan_id)

# Wait for active scan
while True:
    status_resp = requests.get(f"{base_url}/JSON/ascan/view/status/", params={"scanId": scan_id, "apikey": api_key}, headers=headers)
    status = status_resp.json().get("status", "0")
    if int(status) == 100:
        break
    print(f"Active scan progress: {status}%")
    time.sleep(5)
print("Scan complete.")

# Fetch alerts (JSON) - debug
print("Fetching alerts for debugging...")
alerts_resp = requests.get(f"{base_url}/JSON/core/view/alerts/", params={"baseurl": target, "apikey": api_key}, headers=headers)
print("Alerts status:", alerts_resp.status_code)
try:
    alerts = alerts_resp.json()
    alert_list = alerts.get("alerts", [])
    print(f"Found {len(alert_list)} alerts.")
    for a in alert_list:
        print(f"Risk: {a.get('risk')}, Name: {a.get('name')}, URL: {a.get('url')}")
except ValueError:
    print("Unable to parse alerts JSON:", alerts_resp.text)

# Generate HTML report (OTHER)
time.sleep(2)  # small wait to ensure session is settled
print("Generating report (OTHER/core/other/htmlreport)...")
report_resp = requests.get(f"{base_url}/OTHER/core/other/htmlreport/", params={"apikey": api_key}, headers=headers)

print("Report status:", report_resp.status_code)
print("Report content-length header:", report_resp.headers.get("Content-Length"))
print("Report text length (len of content):", len(report_resp.content))

# ensure directory exists
os.makedirs("reports", exist_ok=True)
with open("reports/zap_report.html", "wb") as f:
    f.write(report_resp.content)

print("Report saved to reports/zap_report.html")
