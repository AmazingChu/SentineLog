# SentineLog

SentineLog is a Python-based log analysis and suspicious IP detection tool.

It analyzes Apache-style web access logs and detects suspicious activity using rule-based and time-window-based detection.

The project is designed as a lightweight security monitoring tool and learning project for log analysis, threat detection, and Python-based cybersecurity automation.


# Features

- IPv4 address validation
- Apache-style access log parsing
- Brute-force login detection
- Directory scanning detection
- Suspicious URL pattern detection
- Time-window based detection
- Heuristic risk scoring
- Risk level classification
- Terminal report generation
- CSV report export
- Automated testing with pytest


# Detection Rules

## Brute Force Detection

Detects repeated failed login attempts within a configured time window.

Default configuration:

5 failed login attempts within 60 seconds


## Directory Scanning Detection

Detects a large number of HTTP 404 responses from the same IP address within a short period.

Default configuration:

10 HTTP 404 responses within 60 seconds

## Suspicious URL Detection

SentinelLog checks requested URLs for suspicious patterns such as:

../
/etc/passwd
.env
wp-admin
phpmyadmin
union select

# Risk Scoring

SentinelLog assigns a heuristic risk score based on detected activity.

Risk levels:

Score       Risk Level
0-24        LOW
25-49       MEDIUM
50-74       HIGH
75-100      CRITICAL

The risk score is a rule-based indicator and should not be interpreted as the probability that an IP address is malicious.

# Project Structure

SentinelLog/
│
├── main.py
│
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── parser.py
│   ├── detector.py
│   └── reporter.py
│
├── tests/
│   └── test_detector.py
│
├── logs/
│   └── sample_access.log
│
├── output/
│
├── .gitignore
├── README.md
├── CHANGELOG.md
└── requirements.txt

# Requirements

- Python 3.10+
- pytest (for automated testing)

# Usage

Run SentinelLog from the project root directory:

python main.py

The program will:
1. Read the configured log file.
2. Parse valid log entries.
3. Analyze activity by IP address.
4. Apply detection rules.
5. Calculate a risk score.
6. Display suspicious IPs.
7. Export the results to CSV.

# Example Output

========== Suspicious IP Report ==========

IP: 198.51.100.77

Total Requests: 13
Failed Logins: 0
Max Failed Logins / 60s: 0

404 Requests: 11
Max 404 Requests / 60s: 11

Suspicious Requests: 3

Risk Score: 52/100
Risk Level: HIGH

Triggered Rules:
- Possible Directory Scanning
- Suspicious URL Patterns

# Roadmap
Planned improvements include:
- Command-line arguments
- JSON report export
- Additional log formats
- Improved URL attack detection
- External threat intelligence integration
- Real-time log monitoring
- Dashboard visualization
- Additional automated tests