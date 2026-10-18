import argparse

from src.parser import parse_log
from src.detector import detect_suspicious_ips
from src.reoprter import generate_report, export_to_csv

OUTPUT_FILE = "output/suspicious_ips.csv"


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="SentineLog - Suspicious IP detection fromn web access logs."
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to the access log file."
    )

    parser.add_argument(
        "--output",
        default="output/suspicious_ips.csv",
        help="Path to the CSV output file."
    )

    return parser.parse_args()


def main():
    """
    Work flow:
    1. Parse the log file
    2. Detect suspicious IP and activity
    3. Display in terminal
    4. Export the result to CSV
    """

    args = parse_arguments()

    logs = parse_log(args.log)

    results = detect_suspicious_ips(logs)

    #Display in terminal
    generate_report(results)

    export_to_csv(results, args.output)

if __name__ == "__main__":
    main()