"""
AEGIS Nexus: Persistence & Integration Node (Main File)

- Option A DB placement: DB stored next to this file (safe default)
- SQLite directory creation (SQLite won’t create folders for you)
- Journal mode defaults to DELETE for compatibility; can be set to WAL if stable
- Oversight timers are daemon threads
- Data Vault entries are hash-chained (tamper-evident)
- No demo / no side effects on import
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Callable, Dict, Optional

SYSTEM_ID = "AEGIS-43-NEXUS-01"

# -------------------------
# Option A: DB next to file
# -------------------------
try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path.cwd()

DB_PATH = BASE_DIR / "aegis_secure.db"
LOG_PATH = BASE_DIR / "aegis_system.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
)


class PersistenceManager:
    """
    SQLite persistence layer:
      - event_logs: operational event stream
      - data_vault: write-once-ish vault with hash chaining for tamper evidence
    """

    def __init__(self, db_path: Path, *, journal_mode: str = "DELETE") -> None:
        self.db_path = Path(db_path)
        self.journal_mode = journal_mode
        self.lock = threading.RLock()
        self._init_db()

    def _ensure_parent_dir(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        self._ensure_parent_dir()
        conn = sqlite3.connect(str(self.db_path))
        conn.execute(f"PRAGMA journal_mode={self.journal_mode};")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self) -> None:
        with self.lock, self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT
                );
                """
            )

            # data_vault is tamper-evident via prev_hash + record_hash
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS data_vault (
                    record_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    label TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    prev_hash TEXT,
                    record_hash TEXT NOT NULL
                );
                """
            )

            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_ts ON event_logs(timestamp);")

    def log_event(self, level: str, module: str, message: str, context: Optional[dict] = None) -> None:
        ts = datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z"
        ctx = json.dumps(context, default=str) if context is not None else None
        with self.lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO event_logs (timestamp, level, module, message, context_json)
                VALUES (?, ?, ?, ?, ?);
                """,
                (ts, level, module, message, ctx),
            )

    @staticmethod
    def _sha256_hex(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _get_last_vault_hash(self, conn: sqlite3.Connection) -> Optional[str]:
        row = conn.execute(
            "SELECT record_hash FROM data_vault ORDER BY timestamp DESC LIMIT 1;"
        ).fetchone()
        return row[0] if row else None

    def vault_store(self, record_id: str, label: str, payload: dict) -> None:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_sha = self._sha256_hex(payload_json.encode("utf-8"))
        ts = datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z"

        with self.lock, self._get_conn() as conn:
            prev_hash = self._get_last_vault_hash(conn)

            # hash the whole record (tamper-evident chain)
            record_blob = json.dumps(
                {
                    "record_id": record_id,
                    "timestamp": ts,
                    "label": label,
                    "payload_sha256": payload_sha,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            record_hash = self._sha256_hex(record_blob)

            conn.execute(
                """
                INSERT INTO data_vault (record_id, timestamp, label, payload_json, payload_sha256, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (record_id, ts, label, payload_json, payload_sha, prev_hash, record_hash),
            )

    def verify_vault_chain(self) -> bool:
        """Verifies hash chaining integrity across data_vault."""
        with self.lock, self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT record_id, timestamp, label, payload_sha256, prev_hash, record_hash
                FROM data_vault ORDER BY timestamp ASC;
                """
            ).fetchall()

        prev = None
        for record_id, ts, label, payload_sha, prev_hash, record_hash in rows:
            if prev_hash != prev:
                logging.error(f"[VAULT_VERIFY] Chain break at {record_id}: prev_hash mismatch.")
                return False

            blob = json.dumps(
                {
                    "record_id": record_id,
                    "timestamp": ts,
                    "label": label,
                    "payload_sha256": payload_sha,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            expected = self._sha256_hex(blob)
            if expected != record_hash:
                logging.error(f"[VAULT_VERIFY] Hash mismatch at {record_id}.")
                return False

            prev = record_hash

        logging.info("[VAULT_VERIFY] Vault chain OK.")
        return True


class IntegrationHub:
    """External integration boundary. Replace stubs with real webhooks/API clients."""

    @staticmethod
    def send_alert(message: str, severity: str) -> None:
        logging.info(f"[EXT_ALERT] Would send '{severity}' alert: {message}")

    @staticmethod
    def execute_firewall_block(ip_address: str) -> bool:
        logging.info(f"[EXT_FIREWALL] Would BLOCK IP {ip_address} (Rule: AEGIS_AUTO_BAN)")
        return True


class OversightEngine:
    """Time-delayed execution with operator veto. (Mode logic can live above this.)"""

    def __init__(self, output_callback: Callable[[str, str, Optional[dict]], None]) -> None:
        self.pending_actions: Dict[str, threading.Timer] = {}
        self.lock = threading.RLock()
        self.output_callback = output_callback

    def schedule_action(
        self,
        *,
        action_id: str,
        description: str,
        delay_seconds: int,
        payload: Callable[[], None],
        context: Optional[dict] = None,
    ) -> None:
        with self.lock:
            if action_id in self.pending_actions:
                self.output_callback(f"[OVERSIGHT] Duplicate ignored: {action_id}", "OVERSIGHT", context)
                return

            self.output_callback(
                f"[OVERSIGHT] PENDING: '{description}'. Executing in {delay_seconds}s unless vetoed.",
                "OVERSIGHT",
                context,
            )

            timer = threading.Timer(delay_seconds, self._execute_wrapper, args=(action_id, description, payload, context))
            timer.daemon = True
            self.pending_actions[action_id] = timer
            timer.start()

    def _execute_wrapper(
        self,
        action_id: str,
        description: str,
        payload: Callable[[], None],
        context: Optional[dict],
    ) -> None:
        with self.lock:
            if action_id not in self.pending_actions:
                return
            self.pending_actions.pop(action_id, None)

        try:
            self.output_callback(f"[OVERSIGHT] TIMEOUT -> AUTO-EXECUTING: {description}", "OVERSIGHT", context)
            payload()
        except Exception as exc:
            self.output_callback(f"[OVERSIGHT] Execution failed for {action_id}: {exc}", "ERROR", context)

    def veto_action(self, action_id: str, user_reason: str, context: Optional[dict] = None) -> bool:
        with self.lock:
            timer = self.pending_actions.get(action_id)
            if not timer:
                self.output_callback(f"[OVERSIGHT] VETO FAILED: {action_id} not found.", "OVERSIGHT", context)
                return False

            timer.cancel()
            self.pending_actions.pop(action_id, None)

        self.output_callback(
            f"[OVERSIGHT] VETOED: {action_id} by Operator. Reason: {user_reason}",
            "OVERSIGHT",
            {**(context or {}), "veto_reason": user_reason},
        )
        return True


class SecurityNexus:
    """Main controller: persistence + integrations + oversight coordination."""

    def __init__(self, *, db_path: Path = DB_PATH, journal_mode: str = "DELETE") -> None:
        self.db = PersistenceManager(db_path, journal_mode=journal_mode)
        self.oversight = OversightEngine(output_callback=self._log_event)
        self._log_event("System Initialization. Database Connected.", "SYSTEM", {"system_id": SYSTEM_ID})

    def _log_event(self, message: str, module: str = "SYSTEM", context: Optional[dict] = None) -> None:
        logging.info(f"[{module}] {message}")
        self.db.log_event("INFO", module, message, context)

    def trigger_threat_response(self, ip_source: str, threat_type: str) -> str:
        context = {"ip": ip_source, "threat_type": threat_type}

        self._log_event(f"Threat Detected: {threat_type} from {ip_source}", "THREAT_INT", context)
        IntegrationHub.send_alert(f"High Severity Threat: {threat_type} ({ip_source})", "HIGH")

        action_id = f"BLOCK-{ip_source.replace('.', '-')}"
        description = f"Firewall Ban for {ip_source}"

        # Store decision intent in vault (optional but governance-friendly)
        vault_id = f"DECISION-{action_id}-{int(datetime.datetime.utcnow().timestamp())}"
        self.db.vault_store(vault_id, "threat_response_intent", {"action_id": action_id, "description": description, **context})

        self.oversight.schedule_action(
            action_id=action_id,
            description=description,
            delay_seconds=10,
            payload=lambda: IntegrationHub.execute_firewall_block(ip_source),
            context=context,
        )
        return action_id