from collections import defaultdict

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

def detect_suspicious_ips(logs):

    ip_stats = defaultdict(lambda: {
        "total": 0,
        "failed_login": 0,
        "not_found": 0,
        "suspicious_requests": 0
    })

    for log in logs:
        ip = log['ip']
        method = log['method']
        path = log['path']
        status_code = log['status_code']

        ip_stats[ip]["total"] += 1

        if method == 'POST' and path == '/login' and status_code == 401:
            ip_stats[ip]["failed_login"] += 1
        
        if status_code == 404:
            ip_stats[ip]["not_found"] += 1

        lower_path = path.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in lower_path:
                ip_stats[ip]["suspicious_requests"] += 1
                break
    
    result = []

    for ip, stats in ip_stats.items():
        
        triggered_rules = []

        if stats["failed_login"] >= FAILED_LOGIN_THRESHOLD:
            triggered_rules.append("Possible Brute Force")

        if stats["not_found"] >= NOT_FOUND_THRESHOLD:
            triggered_rules.append("Possible Directory Scanning")

        if stats["suspicious_requests"] >= SUSPICIOUS_REQUEST_THRESHOLD:
            triggered_rules.append("Suspicious URL Patterns")

        if triggered_rules:
            result.append({
                "ip": ip,
                "total": stats["total"],
                "failed_login": stats["failed_login"],
                "not_found": stats["not_found"],
                "suspicious_requests": stats["suspicious_requests"],
                "triggered_rules": triggered_rules
            })
    return result