from src.parser import parse_log
from src.detector import detect_suspicious_ips
from src.reoprter import generate_report, export_to_csv

LOG_FILE = "logs/sample_access.log"
OUTPUT_FILE = "output/suspicious_ips.csv"

def main():
    """
    Work flow:
    1. Parse the log file
    2. Detect suspicious IP and activity
    3. Display in terminal
    4. Export the result to CSV
    """
    logs = parse_log(LOG_FILE)

    results = detect_suspicious_ips(logs)

    #Display in terminal
    generate_report(results)

    export_to_csv(results, OUTPUT_FILE)

if __name__ == "__main__":
    main()