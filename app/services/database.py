"""
Database Service — SQLite storage for incident history.

Stores analysis results so analysts can review past incidents,
track trends, and reference previous findings.
"""

import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "incidents.db"


def _get_connection() -> sqlite3.Connection:
    """Get a database connection, creating tables if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL,
            summary TEXT,
            attack_vector TEXT,
            ioc_count INTEGER DEFAULT 0,
            analysis_duration_ms INTEGER,
            full_result TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def save_incident(analysis_result: dict) -> bool:
    """
    Save an analysis result to the database.

    Args:
        analysis_result: Full AnalysisResponse as a dict

    Returns:
        True if saved successfully
    """
    try:
        conn = _get_connection()
        classification = analysis_result.get("classification", {})
        iocs = analysis_result.get("iocs", {})

        # Count total IOCs
        ioc_count = sum(
            len(iocs.get(key, []))
            for key in ["ip_addresses", "domains", "hashes", "urls", "emails", "filenames", "cves"]
        )

        conn.execute(
            """INSERT OR REPLACE INTO incidents
               (id, timestamp, incident_type, severity, confidence, summary,
                attack_vector, ioc_count, analysis_duration_ms, full_result)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                analysis_result["id"],
                analysis_result["timestamp"],
                classification.get("incident_type", "Unknown"),
                classification.get("severity", "MEDIUM"),
                classification.get("confidence", 0),
                classification.get("summary", ""),
                classification.get("attack_vector", ""),
                ioc_count,
                analysis_result.get("analysis_duration_ms", 0),
                json.dumps(analysis_result),
            )
        )
        conn.commit()
        conn.close()
        logger.info(f"Saved incident {analysis_result['id']} to database")
        return True

    except Exception as e:
        logger.error(f"Failed to save incident: {e}")
        return False


def get_incidents(limit: int = 50, offset: int = 0) -> list[dict]:
    """
    Retrieve past incidents, most recent first.

    Returns list of summary dicts (not the full result).
    """
    try:
        conn = _get_connection()
        rows = conn.execute(
            """SELECT id, timestamp, incident_type, severity, confidence,
                      summary, attack_vector, ioc_count, analysis_duration_ms
               FROM incidents
               ORDER BY timestamp DESC
               LIMIT ? OFFSET ?""",
            (limit, offset)
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    except Exception as e:
        logger.error(f"Failed to retrieve incidents: {e}")
        return []


def get_incident_by_id(incident_id: str) -> Optional[dict]:
    """Retrieve a full incident result by ID."""
    try:
        conn = _get_connection()
        row = conn.execute(
            "SELECT full_result FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()
        conn.close()

        if row:
            return json.loads(row["full_result"])
        return None

    except Exception as e:
        logger.error(f"Failed to retrieve incident {incident_id}: {e}")
        return None


def get_incident_count() -> int:
    """Get total number of stored incidents."""
    try:
        conn = _get_connection()
        count = conn.execute("SELECT COUNT(*) as cnt FROM incidents").fetchone()["cnt"]
        conn.close()
        return count
    except Exception:
        return 0
