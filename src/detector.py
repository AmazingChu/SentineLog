from collections import defaultdict, deque
from datetime import timedelta

#Detection Thresholds
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_SECONDS = 60

NOT_FOUND_THRESHOLD = 10
NOT_FOUND_WINDOW_SECONDS = 60

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
        "suspicious_requests": 0,
        "max_failed_logins_in_window": 0,
        "max_404_in_window": 0
    })

    #Store timestamps belonging to the active detection windows.
    failed_login_window = defaultdict(deque)
    not_found_windows = defaultdict(deque)

    sorted_logs = sorted(logs, key=lambda log: log["timestamp"])

    #Build statistics for each IP address.
    for log in sorted_logs:

        ip = log['ip']
        timestamp = log['timestamp']
        method = log['method']
        path = log['path']
        status_code = log['status_code']

        ip_stats[ip]["total"] += 1

        #---------------------
        #Brute force detection
        #---------------------
        if method == "POST" and path == "/login" and status_code == 401:
            ip_stats[ip]['failed_login'] += 1
            window = failed_login_window[ip]

            window.append(timestamp)

            cutoff = timestamp - timedelta(seconds=FAILED_LOGIN_WINDOW_SECONDS)

            while window and window[0] < cutoff:
                window.popleft()
            
            ip_stats[ip]['max_failed_logins_in_window'] = max(ip_stats[ip]["max_failed_logins_in_window"], len(window))


        #----------------------------
        #Directory scanning detection
        #----------------------------
        if status_code == 404:
            ip_stats[ip]["not_found"] += 1

            window = not_found_windows[ip]
            window.append(timestamp)

            cutoff = timestamp - timedelta(seconds=NOT_FOUND_WINDOW_SECONDS)

            while window and window[0] < cutoff:
                window.popleft()

            ip_stats[ip]["max_404_in_window"] = max(ip_stats[ip]["max_404_in_window"], len(window))

        #------------------------
        #Suspicious URL detection
        #------------------------

        lower_path = path.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in lower_path:

                ip_stats[ip]["suspicious_requests"] += 1
                break

    result = []

    #Evalute each IP against the detection thresholds
    for ip, stats in ip_stats.items():
        
        triggered_rules = []

        if stats["max_failed_logins_in_window"] >= FAILED_LOGIN_THRESHOLD:
            triggered_rules.append(
                f"Possible Brute Force"
                f"({FAILED_LOGIN_THRESHOLD}+ failures /"
                f"{FAILED_LOGIN_WINDOW_SECONDS}s)"
                )

        if stats["max_404_in_window"] >= NOT_FOUND_THRESHOLD:
            triggered_rules.append(
                f"Possible Directory Scanning"
                f"({NOT_FOUND_THRESHOLD}+ 404 responses /"
                f"{NOT_FOUND_WINDOW_SECONDS}s)"
                )

        if stats["suspicious_requests"] >= SUSPICIOUS_REQUEST_THRESHOLD:
            triggered_rules.append("Suspicious URL Patterns")

        #Only include IPs that triggered at least one rule.
        if triggered_rules:

            risk_score = calculate_risk_score(stats)
            risk_level = get_risk_level(risk_score)

            result.append({
                "ip": ip,
                "total": stats["total"],
                "failed_login": stats["failed_login"],
                "not_found": stats["not_found"],
                "suspicious_requests": stats["suspicious_requests"],
                "max_failed_logins_in_window": stats["max_failed_logins_in_window"],
                "max_404_in_window": stats["max_404_in_window"],
                "risk_score": risk_score,
                "risk_level": risk_level,
                "triggered_rules": triggered_rules
            })
    return result

def calculate_risk_score(stats):
    """
    Calculate a heuristic risk score from 0 to 100.
    """

    score = 0

    #Brute force activity

    if stats["max_failed_logins_in_window"] >= FAILED_LOGIN_THRESHOLD:
        score += min(stats["max_failed_logins_in_window"] * 5, 40)

    #Directory scanning activity

    if stats["max_404_in_window"] >= NOT_FOUND_THRESHOLD:
        score += min(stats["max_404_in_window"] * 2, 30)

    #Suspicious URL activity

    if stats["suspicious_requests"] >= SUSPICIOUS_REQUEST_THRESHOLD:
        score += min(stats["suspicious_requests"] * 10, 30)

    return min(score, 100)


def get_risk_level(score):
    """
    Convert the numeric risk score into a risk level
    """

    if score >= 75:
        return "CRITICAL"
    
    if score >= 50:
        return "HIGH"
    
    if score >= 25:
        return "MEDIUM"
    
    return "LOW"
    e