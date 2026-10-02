import json
import tempfile
import unittest
from pathlib import Path

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_DIR))

from ss7_sentinel import (  # noqa: E402
    AlertDatabase,
    analyze_events,
    detect_event_burst,
    detect_invalid_destination,
    detect_repeated_query_pattern,
    detect_unknown_source,
    detect_unexpected_event,
    EXPECTED_EVENTS,
    ALLOWED_DESTINATIONS,
)


class SentinelDetectionTests(unittest.TestCase):

    def test_unknown_source(self):
        event = {
            "source": "UNKNOWN",
            "destination": "HLR-A",
            "event": "LOCATION_QUERY",
        }

        alert = detect_unknown_source(
            event,
            {"MSC-A", "HLR-A"},
        )

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["type"],
            "UNKNOWN_SOURCE",
        )

    def test_trusted_source(self):
        event = {
            "source": "MSC-A",
            "destination": "HLR-A",
            "event": "LOCATION_QUERY",
        }

        alert = detect_unknown_source(
            event,
            {"MSC-A", "HLR-A"},
        )

        self.assertIsNone(alert)

    def test_unexpected_event(self):
        event = {
            "source": "MSC-A",
            "destination": "HLR-A",
            "event": "UNKNOWN_EVENT",
        }

        alert = detect_unexpected_event(
            event,
            EXPECTED_EVENTS,
        )

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["type"],
            "UNEXPECTED_EVENT",
        )

    def test_invalid_destination(self):
        event = {
            "source": "MSC-A",
            "destination": "INVALID-NODE",
            "event": "LOCATION_QUERY",
        }

        alert = detect_invalid_destination(
            event,
            ALLOWED_DESTINATIONS,
        )

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["type"],
            "INVALID_DESTINATION",
        )

    def test_event_burst(self):
        events = []

        for second in range(5):
            events.append(
                {
                    "timestamp": (
                        f"2026-10-01T10:00:0{second}Z"
                    ),
                    "source": "MSC-A",
                    "destination": "HLR-A",
                    "event": "LOCATION_QUERY",
                }
            )

        alerts = detect_event_burst(
            events,
            threshold=5,
            window_seconds=30,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["type"],
            "HIGH_EVENT_VOLUME",
        )

    def test_repeated_pattern(self):
        events = [
            {
                "source": "UNKNOWN",
                "destination": "HLR-A",
                "event": "LOCATION_QUERY",
            }
            for _ in range(3)
        ]

        alerts = detect_repeated_query_pattern(
            events,
            repeated_count=3,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["type"],
            "REPEATED_SUSPICIOUS_QUERY",
        )

    def test_full_analysis(self):
        events = [
            {
                "timestamp": "2026-10-01T10:00:00Z",
                "source": "UNKNOWN",
                "destination": "HLR-A",
                "event": "LOCATION_QUERY",
            },
            {
                "timestamp": "2026-10-01T10:00:01Z",
                "source": "UNKNOWN",
                "destination": "HLR-A",
                "event": "LOCATION_QUERY",
            },
            {
                "timestamp": "2026-10-01T10:00:02Z",
                "source": "UNKNOWN",
                "destination": "HLR-A",
                "event": "LOCATION_QUERY",
            },
        ]

        alerts = analyze_events(
            events,
            {"MSC-A", "HLR-A"},
            threshold=5,
            window_seconds=30,
            repeat_count=3,
        )

        alert_types = {
            alert["type"]
            for alert in alerts
        }

        self.assertIn(
            "UNKNOWN_SOURCE",
            alert_types,
        )

        self.assertIn(
            "REPEATED_SUSPICIOUS_QUERY",
            alert_types,
        )


class DatabaseTests(unittest.TestCase):

    def test_alert_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = (
                Path(directory)
                / "test.db"
            )

            db = AlertDatabase(
                str(db_path)
            )

            alert = {
                "severity": "HIGH",
                "type": "UNKNOWN_SOURCE",
                "source": "UNKNOWN",
                "destination": "HLR-A",
                "event": "LOCATION_QUERY",
                "message": "Test alert",
                "score": 90,
                "extra": {},
            }

            first = db.store_alert(
                alert,
                dedup_window_hours=24,
            )

            second = db.store_alert(
                alert,
                dedup_window_hours=24,
            )

            self.assertTrue(first)
            self.assertFalse(second)

            recent = db.get_recent_alerts(
                hours=24
            )

            self.assertEqual(
                len(recent),
                1,
            )

            self.assertEqual(
                recent[0]["event_count"],
                2,
            )


if __name__ == "__main__":
    unittest.main()
