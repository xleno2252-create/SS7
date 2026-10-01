
import json
import argparse
from collections import Counter
from datetime import datetime

# Simulated telecom signalling events
EVENTS = [
    {
        "source": "MSC-A",
        "destination": "HLR-A",
        "event": "LOCATION_QUERY"
    },
    {
        "source": "MSC-B",
        "destination": "HLR-A",
        "event": "LOCATION_QUERY"
    },
    {
        "source": "UNKNOWN-NODE",
        "destination": "HLR-A",
        "event": "LOCATION_QUERY"
    },
    {
        "source": "MSC-A",
        "destination": "SMSC-A",
        "event": "SMS_ROUTE"
    },
    {
        "source": "UNKNOWN-NODE",
        "destination": "HLR-A",
        "event": "LOCATION_QUERY"
    }
]

# Authorized simulated network nodes
TRUSTED_NODES = {
    "MSC-A",
    "MSC-B",
    "HLR-A",
    "SMSC-A"
}


def analyse_events(events):
    alerts = []
    source_counts = Counter()

    for event in events:
        source = event["source"]
        destination = event["destination"]

        source_counts[source] += 1

        if source not in TRUSTED_NODES:
            alerts.append({
                "severity": "HIGH",
                "type": "UNKNOWN_SOURCE",
                "source": source,
                "destination": destination,
                "message": "Unrecognized simulated network node"
            })

    for source, count in source_counts.items():
        if count >= 5:
            alerts.append({
                "severity": "MEDIUM",
                "type": "HIGH_EVENT_VOLUME",
                "source": source,
                "count": count,
                "message": "Unusually high event volume"
            })

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="SS7 Sentinel - Educational Telecom Monitor"
    )

    parser.add_argument(
        "--report",
        default="sentinel_report.json",
        help="Output report filename"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("          SS7 SENTINEL")
    print("   Telecom Security Monitor")
    print("=" * 50)

    print("\n[+] Analysing simulated events...\n")

    alerts = analyse_events(EVENTS)

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['type']}: {alert['message']}"
        )

        print(f"    Source: {alert['source']}")

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_events": len(EVENTS),
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with open(args.report, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n[+] Analysis complete.")
    print(f"[+] Events analysed: {len(EVENTS)}")
    print(f"[+] Alerts generated: {len(alerts)}")
    print(f"[+] Report saved: {args.report}")


if __name__ == "__main__":
    main()
