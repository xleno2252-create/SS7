#!/usr/bin/env python3
"""
SS7 Sentinel - Defensive Telecom Security Monitor

Educational, simulation-only SS7-style event monitoring tool.

This project does NOT connect to real SS7 networks, telecom operators,
SIM cards, mobile infrastructure, or signalling gateways.
"""

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ============================================================
# Configuration
# ============================================================

class Config:
    """Application configuration loaded from environment variables."""

    DEBUG = os.getenv("SS7_DEBUG", "false").lower() == "true"
    LOG_LEVEL = os.getenv("SS7_LOG_LEVEL", "INFO").upper()
    LOG_FORMAT = os.getenv("SS7_LOG_FORMAT", "json").lower()

    DB_PATH = os.getenv("SS7_DB_PATH", "ss7_sentinel.db")
    REPORT_PATH = os.getenv("SS7_REPORT_PATH", "report.json")

    BURST_THRESHOLD = int(
        os.getenv("SS7_BURST_THRESHOLD", "5")
    )
    BURST_WINDOW_SECONDS = int(
        os.getenv("SS7_BURST_WINDOW_SECONDS", "30")
    )
    REPEAT_COUNT = int(
        os.getenv("SS7_REPEAT_COUNT", "3")
    )

    DEDUP_WINDOW_HOURS = int(
        os.getenv("SS7_DEDUP_WINDOW_HOURS", "24")
    )

    TRUSTED_NODES = {
        node.strip()
        for node in os.getenv(
            "SS7_TRUSTED_NODES",
            "MSC-A,MSC-B,HLR-A,SMSC-A,VLR-A"
        ).split(",")
        if node.strip()
    }

    @classmethod
    def validate(cls) -> None:
        """Validate configuration values."""

        valid_levels = {
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        }

        if cls.LOG_LEVEL not in valid_levels:
            raise ValueError(
                f"Invalid SS7_LOG_LEVEL: {cls.LOG_LEVEL}"
            )

        if cls.BURST_THRESHOLD < 1:
            raise ValueError("BURST_THRESHOLD must be >= 1")

        if cls.BURST_WINDOW_SECONDS < 1:
            raise ValueError("BURST_WINDOW_SECONDS must be >= 1")

        if cls.REPEAT_COUNT < 1:
            raise ValueError("REPEAT_COUNT must be >= 1")

        if cls.DEDUP_WINDOW_HOURS < 1:
            raise ValueError("DEDUP_WINDOW_HOURS must be >= 1")

        if not cls.TRUSTED_NODES:
            raise ValueError("At least one trusted node is required")

    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        return {
            "debug": cls.DEBUG,
            "log_level": cls.LOG_LEVEL,
            "log_format": cls.LOG_FORMAT,
            "db_path": cls.DB_PATH,
            "report_path": cls.REPORT_PATH,
            "burst_threshold": cls.BURST_THRESHOLD,
            "burst_window_seconds": cls.BURST_WINDOW_SECONDS,
            "repeat_count": cls.REPEAT_COUNT,
            "dedup_window_hours": cls.DEDUP_WINDOW_HOURS,
            "trusted_nodes": sorted(cls.TRUSTED_NODES),
        }


# ============================================================
# Logging
# ============================================================

class StructuredFormatter(logging.Formatter):
    """Simple JSON formatter for structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }

        extra_fields = getattr(record, "structured", None)

        if isinstance(extra_fields, dict):
            payload.update(extra_fields)

        if record.exc_info:
            payload["exception"] = self.formatException(
                record.exc_info
            )

        return json.dumps(payload)


class StructuredLogger:
    """Wrapper around Python logging."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self._setup()

    def _setup(self) -> None:
        if self.logger.handlers:
            return

        level = getattr(
            logging,
            Config.LOG_LEVEL,
            logging.INFO
        )

        self.logger.setLevel(level)

        handler = logging.StreamHandler(sys.stdout)

        if Config.LOG_FORMAT == "json":
            handler.setFormatter(StructuredFormatter())
        else:
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s "
                    "[%(levelname)s] "
                    "%(name)s: "
                    "%(message)s"
                )
            )

        self.logger.addHandler(handler)
        self.logger.propagate = False

    def _log(
        self,
        level: int,
        message: str,
        **kwargs: Any,
    ) -> None:
        self.logger.log(
            level,
            message,
            extra={"structured": kwargs},
        )

    def debug(self, message: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, message, **kwargs)


logger = StructuredLogger("ss7_sentinel")


# ============================================================
# Telecom simulation definitions
# ============================================================

EXPECTED_EVENTS: Dict[str, Set[str]] = {
    "MSC-A": {
        "LOCATION_QUERY",
        "SMS_ROUTE",
        "CALL_SETUP",
    },
    "MSC-B": {
        "LOCATION_QUERY",
        "SMS_ROUTE",
        "CALL_SETUP",
    },
    "HLR-A": {
        "LOCATION_QUERY",
        "SUBSCRIBER_PROFILE",
    },
    "SMSC-A": {
        "SMS_ROUTE",
    },
    "VLR-A": {
        "LOCATION_UPDATE",
        "LOCATION_QUERY",
    },
}

ALLOWED_DESTINATIONS: Dict[str, Set[str]] = {
    "MSC-A": {
        "HLR-A",
        "SMSC-A",
        "VLR-A",
    },
    "MSC-B": {
        "HLR-A",
        "SMSC-A",
        "VLR-A",
    },
    "HLR-A": {
        "MSC-A",
        "MSC-B",
        "VLR-A",
    },
    "SMSC-A": {
        "MSC-A",
        "MSC-B",
    },
    "VLR-A": {
        "HLR-A",
        "MSC-A",
        "MSC-B",
    },
}


# ============================================================
# Utilities
# ============================================================

def utc_now() -> datetime:
    """Return current timezone-aware UTC time."""
    return datetime.now(timezone.utc)


def parse_timestamp(
    value: Optional[str],
) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp into UTC."""

    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(timezone.utc)

    except (TypeError, ValueError) as exc:
        logger.warning(
            "Failed to parse timestamp",
            value=value,
            error=str(exc),
        )
        return None


def load_events(
    path: Optional[str],
) -> List[Dict[str, Any]]:
    """Load simulated events from JSON."""

    if not path:
        logger.info(
            "No input file supplied",
            source="empty",
        )
        return []

    input_path = Path(path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    with input_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            "Input JSON must contain a list of events"
        )

    for index, event in enumerate(data):
        if not isinstance(event, dict):
            raise ValueError(
                f"Event at index {index} must be an object"
            )

    logger.info(
        "Events loaded",
        path=str(input_path),
        count=len(data),
    )

    return data


def make_alert(
    severity: str,
    alert_type: str,
    source: str,
    destination: str,
    event: str,
    message: str,
    score: int,
    **extra: Any,
) -> Dict[str, Any]:
    """Create a normalized alert dictionary."""

    return {
        "severity": severity,
        "type": alert_type,
        "source": source,
        "destination": destination,
        "event": event,
        "message": message,
        "score": score,
        "extra": extra,
    }


# ============================================================
# Detection rules
# ============================================================

def detect_unknown_source(
    event: Dict[str, Any],
    trusted_nodes: Set[str],
) -> Optional[Dict[str, Any]]:
    """Detect events originating from unknown nodes."""

    source = event.get("source", "")

    if source and source not in trusted_nodes:
        return make_alert(
            "HIGH",
            "UNKNOWN_SOURCE",
            source,
            event.get("destination", "N/A"),
            event.get("event", "UNKNOWN"),
            "Unrecognized network node",
            90,
        )

    return None


def detect_unexpected_event(
    event: Dict[str, Any],
    expected_events: Dict[str, Set[str]],
) -> Optional[Dict[str, Any]]:
    """Detect unexpected event types from known nodes."""

    source = event.get("source", "")
    event_name = event.get("event", "")

    if source not in expected_events:
        return None

    if event_name not in expected_events[source]:
        return make_alert(
            "MEDIUM",
            "UNEXPECTED_EVENT",
            source,
            event.get("destination", "N/A"),
            event_name,
            f"Unexpected event type for node: {event_name}",
            60,
        )

    return None


def detect_invalid_destination(
    event: Dict[str, Any],
    allowed_destinations: Dict[str, Set[str]],
) -> Optional[Dict[str, Any]]:
    """Detect invalid source/destination combinations."""

    source = event.get("source", "")
    destination = event.get("destination", "")

    if source not in allowed_destinations:
        return None

    if destination not in allowed_destinations[source]:
        return make_alert(
            "MEDIUM",
            "INVALID_DESTINATION",
            source,
            destination,
            event.get("event", "UNKNOWN"),
            "Destination is not valid for this source",
            65,
        )

    return None


def detect_event_burst(
    events: List[Dict[str, Any]],
    threshold: int = 5,
    window_seconds: int = 30,
) -> List[Dict[str, Any]]:
    """Detect unusually high event volume from one source."""

    source_times: Dict[str, List[datetime]] = defaultdict(list)

    for event in events:
        timestamp = parse_timestamp(
            event.get("timestamp")
        )
        source = event.get("source")

        if timestamp and source:
            source_times[source].append(timestamp)

    alerts: List[Dict[str, Any]] = []

    for source, times in source_times.items():
        times.sort()

        for current_time in times:
            window_start = (
                current_time
                - timedelta(seconds=window_seconds)
            )

            count = sum(
                1
                for timestamp in times
                if window_start <= timestamp <= current_time
            )

            if count >= threshold:
                alerts.append(
                    make_alert(
                        "MEDIUM",
                        "HIGH_EVENT_VOLUME",
                        source,
                        "MULTIPLE",
                        "MULTIPLE_EVENTS",
                        (
                            "Unusually high event volume "
                            f"detected in {window_seconds}s window"
                        ),
                        min(85, 50 + count * 5),
                        count=count,
                        window_seconds=window_seconds,
                    )
                )
                break

    return alerts


def detect_repeated_query_pattern(
    events: List[Dict[str, Any]],
    repeated_count: int = 3,
) -> List[Dict[str, Any]]:
    """Detect repeated simulated event patterns."""

    counter: Counter = Counter()

    for event in events:
        key = (
            event.get("source", ""),
            event.get("event", ""),
            event.get("destination", ""),
        )

        if key[0] and key[1]:
            counter[key] += 1

    alerts: List[Dict[str, Any]] = []

    for (
        source,
        event_name,
        destination,
    ), count in counter.items():

        if count >= repeated_count:
            alerts.append(
                make_alert(
                    "HIGH",
                    "REPEATED_SUSPICIOUS_QUERY",
                    source,
                    destination,
                    event_name,
                    "Repeated simulated signalling pattern detected",
                    min(95, 60 + count * 10),
                    count=count,
                )
            )

    return alerts


# ============================================================
# Analysis engine
# ============================================================

def analyze_events(
    events: List[Dict[str, Any]],
    trusted_nodes: Set[str],
    threshold: int = 5,
    window_seconds: int = 30,
    repeat_count: int = 3,
) -> List[Dict[str, Any]]:
    """Run all defensive detection rules."""

    logger.info(
        "Starting analysis",
        total_events=len(events),
    )

    alerts: List[Dict[str, Any]] = []

    for event in events:
        detectors = (
            (
                detect_unknown_source,
                trusted_nodes,
            ),
            (
                detect_unexpected_event,
                EXPECTED_EVENTS,
            ),
            (
                detect_invalid_destination,
                ALLOWED_DESTINATIONS,
            ),
        )

        for detector, detector_config in detectors:
            alert = detector(
                event,
                detector_config,
            )

            if alert:
                alerts.append(alert)

    alerts.extend(
        detect_event_burst(
            events,
            threshold=threshold,
            window_seconds=window_seconds,
        )
    )

    alerts.extend(
        detect_repeated_query_pattern(
            events,
            repeated_count=repeat_count,
        )
    )

    alerts.sort(
        key=lambda alert: alert["score"],
        reverse=True,
    )

    logger.info(
        "Analysis complete",
        total_alerts=len(alerts),
    )

    return alerts


# ============================================================
# Database
# ============================================================

class AlertDatabase:
    """SQLite persistence and alert deduplication."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as connection:
            cursor = connection.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_hash TEXT UNIQUE NOT NULL,
                    severity TEXT NOT NULL,
                    type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    event TEXT NOT NULL,
                    message TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    event_count INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    metadata TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_timestamp TEXT NOT NULL,
                    total_events INTEGER NOT NULL,
                    total_alerts INTEGER NOT NULL,
                    duration_ms INTEGER,
                    config_hash TEXT
                )
                """
            )

        logger.info(
            "Database initialized",
            db_path=self.db_path,
        )

    @staticmethod
    def _hash_alert(
        alert: Dict[str, Any],
    ) -> str:
        """Create deterministic SHA-256 alert identifier."""

        key = (
            f"{alert['type']}:"
            f"{alert['source']}:"
            f"{alert['destination']}:"
            f"{alert['event']}"
        )

        return hashlib.sha256(
            key.encode("utf-8")
        ).hexdigest()

    def store_alert(
        self,
        alert: Dict[str, Any],
        dedup_window_hours: int = 24,
    ) -> bool:
        """
        Store an alert.

        Returns True when the alert is new within the dedup window.
        """

        alert_hash = self._hash_alert(alert)
        now = utc_now()
        cutoff = (
            now
            - timedelta(hours=dedup_window_hours)
        ).isoformat()

        with self._connect() as connection:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT id
                FROM alerts
                WHERE alert_hash = ?
                  AND last_seen > ?
                """,
                (alert_hash, cutoff),
            )

            existing = cursor.fetchone()

            if existing:
                cursor.execute(
                    """
                    UPDATE alerts
                    SET last_seen = ?,
                        event_count = event_count + 1
                    WHERE id = ?
                    """,
                    (now.isoformat(), existing[0]),
                )

                return False

            cursor.execute(
                """
                INSERT INTO alerts (
                    alert_hash,
                    severity,
                    type,
                    source,
                    destination,
                    event,
                    message,
                    score,
                    first_seen,
                    last_seen,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_hash,
                    alert["severity"],
                    alert["type"],
                    alert["source"],
                    alert["destination"],
                    alert["event"],
                    alert["message"],
                    alert["score"],
                    now.isoformat(),
                    now.isoformat(),
                    json.dumps(
                        alert.get("extra", {})
                    ),
                ),
            )

        return True

    def get_recent_alerts(
        self,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Return recent persisted alerts."""

        cutoff = (
            utc_now()
            - timedelta(hours=hours)
        ).isoformat()

        with self._connect() as connection:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT
                    severity,
                    type,
                    source,
                    destination,
                    event,
                    message,
                    score,
                    event_count,
                    last_seen
                FROM alerts
                WHERE last_seen > ?
                ORDER BY score DESC
                """,
                (cutoff,),
            )

            rows = cursor.fetchall()

        return [
            {
                "severity": row[0],
                "type": row[1],
                "source": row[2],
                "destination": row[3],
                "event": row[4],
                "message": row[5],
                "score": row[6],
                "event_count": row[7],
                "last_seen": row[8],
            }
            for row in rows
        ]

    def log_run(
        self,
        total_events: int,
        total_alerts: int,
        duration_ms: int,
        config_hash: str,
    ) -> None:
        """Store an analysis-run audit record."""

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO analysis_runs (
                    run_timestamp,
                    total_events,
                    total_alerts,
                    duration_ms,
                    config_hash
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    utc_now().isoformat(),
                    total_events,
                    total_alerts,
                    duration_ms,
                    config_hash,
                ),
            )


# ============================================================
# CLI
# ============================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "SS7 Sentinel - "
            "Defensive Telecom Security Monitor"
        )
    )

    parser.add_argument(
        "--input",
        help="Path to simulated JSON event file",
    )

    parser.add_argument(
        "--report",
        help="Output report path",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        help="Burst detection threshold",
    )

    parser.add_argument(
        "--window",
        type=int,
        help="Burst detection window in seconds",
    )

    parser.add_argument(
        "--repeat-count",
        type=int,
        help="Repeated-pattern threshold",
    )

    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Show current configuration",
    )

    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main() -> int:
    """Application entry point."""

    try:
        Config.validate()
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return 2

    args = parse_args()

    if args.show_config:
        print(
            json.dumps(
                Config.to_dict(),
                indent=4,
            )
        )
        return 0

    start = time.perf_counter()

    logger.info(
        "SS7 Sentinel starting",
        version="1.0.0",
        mode="simulation",
    )

    try:
        events = load_events(args.input)

        threshold = (
            args.threshold
            if args.threshold is not None
            else Config.BURST_THRESHOLD
        )

        window = (
            args.window
            if args.window is not None
            else Config.BURST_WINDOW_SECONDS
        )

        repeat_count = (
            args.repeat_count
            if args.repeat_count is not None
            else Config.REPEAT_COUNT
        )

        alerts = analyze_events(
            events,
            Config.TRUSTED_NODES,
            threshold,
            window,
            repeat_count,
        )

        db = AlertDatabase(Config.DB_PATH)

        new_alerts = 0

        for alert in alerts:
            if db.store_alert(
                alert,
                Config.DEDUP_WINDOW_HOURS,
            ):
                new_alerts += 1

        recent_alerts = db.get_recent_alerts(
            Config.DEDUP_WINDOW_HOURS
        )

        duration_ms = int(
            (time.perf_counter() - start) * 1000
        )

        config_json = json.dumps(
            Config.to_dict(),
            sort_keys=True,
        )

        config_hash = hashlib.sha256(
            config_json.encode("utf-8")
        ).hexdigest()

        db.log_run(
            len(events),
            len(alerts),
            duration_ms,
            config_hash,
        )

        report = {
            "generated_at": utc_now().isoformat(),
            "version": "1.0.0",
            "mode": "simulation",
            "configuration": Config.to_dict(),
            "summary": {
                "total_events": len(events),
                "new_alerts": new_alerts,
                "total_alerts": len(alerts),
                "deduplicated_count": (
                    len(alerts) - new_alerts
                ),
                "recent_alerts": len(recent_alerts),
                "duration_ms": duration_ms,
            },
            "current_run": {
                "alerts": alerts,
            },
        }

        report_path = Path(
            args.report or Config.REPORT_PATH
        )

        report_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with report_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                report,
                file,
                indent=4,
            )

        print("=" * 70)
        print("SS7 SENTINEL - DEFENSIVE TELECOM MONITOR")
        print("=" * 70)
        print()
        print("[✓] Analysis complete")
        print(f"    Events analyzed: {len(events)}")
        print(f"    New alerts: {new_alerts}")
        print(f"    Total alerts: {len(alerts)}")
        print(f"    Duration: {duration_ms}ms")
        print(f"    Report: {report_path}")
        print(f"    Database: {Config.DB_PATH}")

        if alerts:
            print()
            print("[!] Top alerts:")

            for alert in alerts[:5]:
                print(
                    f"    [{alert['severity']}] "
                    f"{alert['type']} - "
                    f"{alert['source']} → "
                    f"{alert['destination']} "
                    f"(score: {alert['score']})"
                )

        return 0

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130

    except Exception:
        logger.critical(
            "Analysis failed",
            exc_info=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
