import os
import csv


def generate_report(results):
    """
    Display suspicious IP detection results in the terminal.

    Args:
        results: Result from scr/detector.py
    """
    print("\n========== Suspicious IP Report ==========")

    if not results:
        print("\nNo suspicious IPs detected.")
        return

    for result in results:

        print(f"\nIP: {result['ip']}")
        print(f"Total Requests: {result['total']}")
        print(f"Failed Logins: {result['failed_login']}")
        print(f"Max Failed Login / 60s: "
              f"{result['max_failed_logins_in_window']}")
        
        print(f"404 Requests: {result['not_found']}")
        print(f"Max 404 Requests / 60s: "
              f"{result['max_404_in_window']}")
        
        print(
            f"Suspicious Requests: "
            f"{result['suspicious_requests']}"
        )

        print("\nTriggered Rules:")

        for rule in result["triggered_rules"]:
            print(f"- {rule}")

        print("------------------------------------------")

    print(f"\nTotal Suspicious IPs: {len(results)}")

def export_to_csv(results, output_file):
    """
    Export suspicious IP detection results to a CSV file.

    Args:
        results: Detection result returned by src/detector.py detect_suspicious_ips().
        output_file: Destination path for the CSV output report.
    """

    #Create the output directory if it does not exist.
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", newline="", encoding="utf-8") as file:

        fieldnames = [
            "ip",
            "total_requests",
            "failed_logins",
            "max_failed_logins_60s",
            "not_found_requests",
            "max_404_requests_60s",
            "suspicious_requests",
            "triggered_rules"
        ] 

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for result in results:

            writer.writerow({
                "ip": result["ip"],
                "total_requests": result["total"],
                "failed_logins": result["failed_login"],
                "max_failed_logins_60s":
                    result["max_failed_logins_in_window"],
                "not_found_requests": result["not_found"],
                "max_404_requests_60s":
                    result["max_404_in_window"],
                "suspicious_requests":
                    result["suspicious_requests"],
                "triggered_rules":
                    "; ".join(result["triggered_rules"])
            })

    print(f"\nCSV report saved to: {output_file}")