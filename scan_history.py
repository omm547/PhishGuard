"""Small SQLite-backed storage for PhishGuard scan history."""

from datetime import datetime, timedelta, timezone
import logging
import sqlite3
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


LOGGER = logging.getLogger(__name__)
MAX_HISTORY_RECORDS = 100
DATABASE_PATH = Path(__file__).with_name("scan_history.db")
UTC_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

try:
    IST = ZoneInfo("Asia/Kolkata")
except ZoneInfoNotFoundError:
    # India has no daylight-saving changes, so this fixed offset is a safe
    # fallback on systems that do not ship an IANA timezone database.
    IST = timezone(timedelta(hours=5, minutes=30), name="IST")


class HistoryError(Exception):
    """A safe, user-facing history storage error."""


def _connect():
    connection = sqlite3.connect(DATABASE_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_history():
    """Create the local history table when the application first needs it."""
    try:
        with _connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    submitted_url TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_category TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at "
                "ON scan_history (scanned_at DESC, id DESC)"
            )
    except sqlite3.Error as error:
        LOGGER.exception("Could not initialize scan history")
        raise HistoryError from error


def save_scan(submitted_url, analysis):
    """Store one completed analysis; return False if history storage is unavailable."""
    try:
        initialize_history()
        with _connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_history
                    (scanned_at, submitted_url, risk_score, risk_category)
                VALUES (?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).strftime(UTC_TIMESTAMP_FORMAT),
                    submitted_url,
                    int(analysis["score"]),
                    analysis["category"],
                ),
            )
        return True
    except (HistoryError, sqlite3.Error, KeyError, TypeError, ValueError) as error:
        LOGGER.exception("Could not save scan history")
        return False


def get_recent_scans(limit=MAX_HISTORY_RECORDS):
    """Return recent records, newest first, with a hard upper limit."""
    safe_limit = max(1, min(int(limit), MAX_HISTORY_RECORDS))
    try:
        initialize_history()
        with _connect() as connection:
            rows = connection.execute(
                """
                SELECT scanned_at, submitted_url, risk_score, risk_category
                FROM scan_history
                ORDER BY scanned_at DESC, id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [
            {
                **dict(row),
                "displayed_at": _format_timestamp_ist(row["scanned_at"]),
            }
            for row in rows
        ]
    except (sqlite3.Error, ValueError) as error:
        LOGGER.exception("Could not load scan history")
        raise HistoryError from error


def _format_timestamp_ist(stored_timestamp):
    """Convert the stored UTC timestamp to a clearly labeled IST display value."""
    stored_datetime = datetime.strptime(stored_timestamp, UTC_TIMESTAMP_FORMAT).replace(
        tzinfo=timezone.utc
    )
    ist_datetime = stored_datetime.astimezone(IST)
    display_value = ist_datetime.strftime("%d %b %Y, %I:%M %p IST")
    return display_value.replace(", 0", ", ")


def clear_history():
    """Delete all locally stored scan history."""
    try:
        initialize_history()
        with _connect() as connection:
            connection.execute("DELETE FROM scan_history")
    except sqlite3.Error as error:
        LOGGER.exception("Could not clear scan history")
        raise HistoryError from error
