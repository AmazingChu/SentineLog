from src.parser import parse_log
from src.detector import detect_suspicious_ips
from src.reoprter import generate_report
from collections import defaultdict

LOG_FILE = "logs/sample_access.log"

def main():

    logs = parse_log(LOG_FILE)

    results = detect_suspicious_ips(logs)

    generate_report(results)

if __name__ == "__main__":
    main()