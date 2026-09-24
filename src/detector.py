from collections import defaultdict

#Detection Thresholds
FAILED_LOGIN_THRESHOLD = 5
NOT_FOUND_THRESHOLD = 10
SUSPICIOUS_REQUEST_THRESHOLD = 3

#Common URL patterns associatedwith suspicious web activity
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
    """
    Analyze parsed logs and identify suspicious IP address.

    Detection Rules:
        1. Repeat failed login attempts.
        2. Large number of HTTP 404 responses.
        3. Requests containing suspicious URL patterns.

    Args:
        logs: Parsed log entries return by src/parser.py parse_log().

    Returns:
        A list containing suspicious IP statistics and triggered rules.
    """
    ip_stats = defaultdict(lambda: {
        "total": 0,
        "failed_login": 0,
        "not_found": 0,
        "suspicious_requests": 0
    })

    #Build statistics for each IP address.
    for log in logs:
        ip = log['ip']
        method = log['method']
        path = log['path']
        status_code = log['status_code']

        ip_stats[ip]["total"] += 1

        #Detect repeated failed login attempts.
        if method == 'POST' and path == '/login' and status_code == 401:
            ip_stats[ip]["failed_login"] += 1
        
        #Large numbers of 404 responses may indicate directory scanning.
        if status_code == 404:
            ip_stats[ip]["not_found"] += 1

        lower_path = path.lower()

        #Check the requested path for known suspicious patterns.
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in lower_path:
                ip_stats[ip]["suspicious_requests"] += 1
                break
    
    result = []

    #Evalute each IP against the detection thresholds
    for ip, stats in ip_stats.items():
        
        triggered_rules = []

        if stats["failed_login"] >= FAILED_LOGIN_THRESHOLD:
            triggered_rules.append("Possible Brute Force")

        if stats["not_found"] >= NOT_FOUND_THRESHOLD:
            triggered_rules.append("Possible Directory Scanning")

        if stats["suspicious_requests"] >= SUSPICIOUS_REQUEST_THRESHOLD:
            triggered_rules.append("Suspicious URL Patterns")

        #Only include IPs that triggered at least one rule.
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