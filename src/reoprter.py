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