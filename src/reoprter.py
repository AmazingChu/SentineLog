import os
import csv


def generate_report(results):

    print("\n========== Suspicious IP Report ==========")

    if not results:
        print("\nNo suspicious IPs detected.")
        return

    for result in results:

        print(f"\nIP: {result['ip']}")
        print(f"Total Requests: {result['total']}")
        print(f"Failed Logins: {result['failed_login']}")
        print(f"404 Requests: {result['not_found']}")
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

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", newline="", encoding="utf-8") as file:

        fieldnames = [
            "ip",
            "total_requests",
            "failed_logins",
            "not_found_requests",
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
                "not_found_requests": result["not_found"],
                "suspicious_requests": result["suspicious_requests"],
                "triggered_rules": "; ".join(result["triggered_rules"])
            })

    print(f"\nCSV report saved to: {output_file}")