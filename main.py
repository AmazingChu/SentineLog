import re
import ipaddress
from collections import defaultdict

LOG_FILE = "logs/access.log"
FAILED_LOGIN_THRESHOLD = 5
NOT_FOUND_THRESHOLD = 10
SUSPICIOUS_REQUEST_THRESHOLD = 3

SUSPICIOUS_PATTERNS = [
    "../",
    "/etc/passwd",
    ".env",
    "wp-admin",
    "phpmyadmin",
    "union select",
    "<script"
]

ip_pattern = re.compile(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+).*?"\s+(\d{3})')
ip_stats = defaultdict(lambda: {
    "Total": 0,
    "Failed_Login": 0,
    "Not_Found": 0,
    "Suspicious_requests": 0
})

with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file:
        match = ip_pattern.search(line)
        
        if not match:
            continue

        ip = match.group(1)
        method = match.group(2)
        path = match.group(3)
        status_code = int(match.group(4))

        lower_path = path.lower()

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"Is is {ip} a ip address???")

        ip_stats[ip]["Total"] += 1
        if path == "/login" and status_code == 401:
            ip_stats[ip]["Failed_Login"] += 1

        if status_code == 404:
            ip_stats[ip]["Not_Found"] += 1
        
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in lower_path:
                ip_stats[ip]["Suspicious_requests"] += 1
                break


print()
print("\n========== Suspicious IP Report ==========")

alert_count = 0

for ip, stats in ip_stats.items():

    triggered_rules = []

    # Rule 1: Failed login detection
    if stats["Failed_Login"] >= FAILED_LOGIN_THRESHOLD:
        triggered_rules.append("Possible Brute Force")

    # Rule 2: Directory scanning detection
    if stats["Not_Found"] >= NOT_FOUND_THRESHOLD:
        triggered_rules.append("Possible Directory Scanning")

    # Rule 3: Suspicious URL detection
    if stats["Suspicious_requests"] >= SUSPICIOUS_REQUEST_THRESHOLD:
        triggered_rules.append("Suspicious URL Patterns")

    # Skip IPs that did not trigger any rules
    if not triggered_rules:
        continue

    alert_count += 1

    print(f"\nIP: {ip}")

    print(f"Total Requests: {stats['Total']}")
    print(f"Failed Logins: {stats['Failed_Login']}")
    print(f"404 Requests: {stats['Not_Found']}")
    print(f"Suspicious Requests: {stats['Suspicious_requests']}")

    print("\nTriggered Rules:")

    for rule in triggered_rules:
        print(f"- {rule}")

    print("------------------------------------------")


print(f"\nTotal Suspicious IPs: {alert_count}")
print()