import json
import sqlite3
from datetime import datetime, timezone


class WAFLogger:
    def __init__(self, db_path="waf_logs.db"):
        self.db_path = db_path
        self._persistent_conn = None
        if self.db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._initialize_db()

    def _connect(self):
        if self._persistent_conn is not None:
            return self._persistent_conn
        return sqlite3.connect(self.db_path)

    def _initialize_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS waf_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attack_type TEXT,
                    findings TEXT,
                    headers TEXT
                )
                """
            )

    def log_event(self, ip, method, path, status, attack_type=None, findings=None, headers=None):
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO waf_events (timestamp, ip, method, path, status, attack_type, findings, headers)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    ip,
                    method,
                    path,
                    status,
                    attack_type,
                    json.dumps(findings or []),
                    json.dumps(headers or {}),
                ),
            )

    def recent_events(self, limit=100):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, ip, method, path, status, attack_type, findings
                FROM waf_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "timestamp": r[0],
                "ip": r[1],
                "method": r[2],
                "path": r[3],
                "status": r[4],
                "attack_type": r[5],
                "findings": json.loads(r[6] or "[]"),
            }
            for r in rows
        ]

    def stats(self):
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM waf_events").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM waf_events WHERE status = 'blocked'").fetchone()[0]
            allowed = conn.execute("SELECT COUNT(*) FROM waf_events WHERE status = 'allowed'").fetchone()[0]
            by_attack = conn.execute(
                """
                SELECT COALESCE(attack_type, 'none') AS attack_type, COUNT(*)
                FROM waf_events
                GROUP BY attack_type
                ORDER BY COUNT(*) DESC
                """
            ).fetchall()
        return {
            "total": total,
            "blocked": blocked,
            "allowed": allowed,
            "by_attack": [{"attack_type": row[0], "count": row[1]} for row in by_attack],
        }
