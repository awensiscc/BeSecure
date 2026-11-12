import requests
import json
import os
import re
import sys

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "your_abuse_key_here")

ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2/check'

if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_abuse_key_here":
    print("[!] Missing ABUSEIPDB_API_KEY. Set env var ABUSEIPDB_API_KEY.", file=sys.stderr)
    sys.exit(1)

private_ip = re.compile(r'^(?:::1$|(?:10|127|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\..*)')
try:

    with open("connections.json", "r", encoding="utf-8-sig") as file:
        lines = json.load(file)
except FileNotFoundError:
    print("connections.json not found. Run the PowerShell script first.", file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"connections.json is not valid JSON: {e}", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    print(f"Could not read connections.json: {e}", file=sys.stderr)
    sys.exit(1)

checkips = []
for line in lines:
    try:
        ip = line['RemoteAddress']
    except (TypeError, KeyError):
        continue
    if not private_ip.match(ip):
        checkips.append(ip)


url = ABUSEIPDB_API_URL
report = []
for ip in checkips:

    querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
    }

    headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
    }

    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {ip}: {e}", file=sys.stderr)
        continue
    data = json.loads(response.text)

    print(f"IP {ip}:","\nConfidence score:",data["data"]["abuseConfidenceScore"])
    print("Country:",data["data"]["countryCode"])
    print("Is IP whitelisted:", data['data']["isWhitelisted"])
    print('Corresponds to the process on your PC:')
    ip_obj = {
        "Ip": ip,
        "Confidence Score": data["data"]["abuseConfidenceScore"],
        "CountryCode": data["data"]["countryCode"],
        "isWhitelisted": data['data']["isWhitelisted"],
        "Connections": []
    }

    for line in lines:
        if ip in line['RemoteAddress']:
            ip_obj["Connections"].append({
                "Port": line['RemotePort'],
                "Process ID": line['OwningProcess'],
                "Process Name": line['ProcessName']
            })
            print(f"Port:{line['RemotePort']}",f"Process ID:{line['OwningProcess']}",f"Process Name:{line['ProcessName']}")
    print("\n")
    report.append(ip_obj)
with open("report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
print("Saved report.json")
