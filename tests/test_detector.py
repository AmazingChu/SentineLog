from datetime import datetime, timedelta, timezone

from src.detector import detect_suspicious_ips

BASE_TIME = datetime(
    2026, 9, 23,
    14, 0, 0,
    tzinfo=timezone.utc
)

def make_log(ip, seconds, method="GET", path="/", status_code=200):
    return {
        "ip": ip,
        "timestamp": BASE_TIME + timedelta(seconds=seconds),
        "method": method,
        "path": path,
        "status_code": status_code
    }

def test_brute_force_detection():

    logs = []

    for i in range(5):
        logs.append(
            make_log(
                ip="203.0.113.25",
                seconds = i* 5,
                method = "POST",
                path="/login",
                status_code=401
            )
        )
    results = detect_suspicious_ips(logs)

    assert len(results) == 1

    result = results[0]
    
    assert result['ip'] == '203.0.113.25'

    assert (
        "Possible Brute Force"
        in result["triggered_rules"][0]
    )

def test_no_brute_force_outside_time_window():

    logs = []

    for i in range(5):
        logs.append(
            make_log(
                ip="100.100.100.100",
                seconds=i*3600,
                method="POST",
                path="/login",
                status_code=401
            )
        )
    results = detect_suspicious_ips(logs)

    assert len(results) == 0

def test_directory_scanning_detection():

    logs = []

    for i in range(10):
        logs.append(
            make_log(
                ip="198.51.100.77",
                seconds= i * 3,
                path=f"/missing{i}",
                status_code=404
            )
        )

    results = detect_suspicious_ips(logs)

    assert len(results) == 1

    result = results[0]

    assert (
        "Possible Directory Scanning"
        in result["triggered_rules"][0]
    )

def test_suspicious_url_detection():

    logs = [
        make_log(
            "45.67.89.10",
            0,
            path="/../../etc/passwd",
            status_code=403
        ),

        make_log(
            "45.67.89.10",
            5,
            path="/.env",
            status_code=403
        ),

        make_log(
            "45.67.89.10",
            10,
            path="/wp-admin",
            status_code=403
        )
    ]

    results = detect_suspicious_ips(logs)

    assert len(results) == 1

    result = results[0]

    assert (
        "Suspicious URL Patterns"
        in result["triggered_rules"]
    )


def test_normal_ip_not_flagged():

    logs = [
        make_log(
            "192.168.1.10",
            0,
            path="/",
            status_code=200
        ),

        make_log(
            "192.168.1.10",
            10,
            path="/products",
            status_code=200
        ),

        make_log(
            "192.168.1.10",
            20,
            path="/contact",
            status_code=200
        )
    ]

    results = detect_suspicious_ips(logs)

    assert len(results) == 0

def test_risk_score():
     
     logs = []

     for i in range(10):
        logs.append(
            make_log(
                ip="198.51.100.77",
                seconds=i * 3,
                path="/wp-admin",
                status_code=404
            )
        )

     results = detect_suspicious_ips(logs)

     assert len(results) == 1

     result = results[0]

     assert result["risk_score"] > 0

     assert result["risk_level"] in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]
