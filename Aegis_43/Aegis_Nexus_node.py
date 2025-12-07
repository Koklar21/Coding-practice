"""\
AEGIS-42 Nexus: Persistence & Integration Node
"""

import datetime
import logging
import time
import json
import hashlib
import threading
import sqlite3
from typing import Dict, Callable

SYSTEM_ID = "AEGIS-42-NEXUS-01"
DB_FILENAME = "aegis_secure.db"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s',
    handlers=[
        logging.FileHandler("aegis_system.log"),
        logging.StreamHandler(),
    ],
)


class PersistenceManager:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute(
                '''CREATE TABLE IF NOT EXISTS event_logs (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       timestamp TEXT,
                       level TEXT,
                       module TEXT,
                       message TEXT
                   )'''
            )
            c.execute(
                '''CREATE TABLE IF NOT EXISTS data_vault (
                       record_id TEXT PRIMARY KEY,
                       timestamp TEXT,
                       label TEXT,
                       payload_json TEXT,
                       sha256_hash TEXT
                   )'''
            )

    def log_event(self, level: str, module: str, message: str) -> None:
        timestamp = datetime.datetime.utcnow().isoformat()
        with self.lock, self._get_conn() as conn:
            conn.execute(
                "INSERT INTO event_logs (timestamp, level, module, message) VALUES (?, ?, ?, ?)",
                (timestamp, level, module, message),
            )

    def vault_store(self, record_id: str, label: str, payload: dict) -> None:
        payload_str = json.dumps(payload, sort_keys=True)
        digest = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        timestamp = datetime.datetime.utcnow().isoformat()
        with self.lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO data_vault (record_id, timestamp, label, payload_json, sha256_hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                (record_id, timestamp, label, payload_str, digest),
            )


class IntegrationHub:
    @staticmethod
    def send_alert(message: str, severity: str) -> None:
        logging.info(f"[EXT_ALERT] Sending '{severity}' alert via HTTPS: {message}")

    @staticmethod
    def execute_firewall_block(ip_address: str) -> bool:
        logging.info(
            f"[EXT_FIREWALL] API Call -> BLOCK IP {ip_address} (Rule: AEGIS_AUTO_BAN)"
        )
        return True


class OversightEngine:
    def __init__(self, output_callback: Callable[[str, str], None]) -> None:
        self.pending_actions: Dict[str, threading.Timer] = {}
        self.lock = threading.RLock()
        self.output_callback = output_callback

    def schedule_action(
        self,
        action_id: str,
        description: str,
        delay_seconds: int,
        payload: Callable[[], None],
    ) -> None:
        with self.lock:
            if action_id in self.pending_actions:
                return
            self.output_callback(
                f"[OVERSIGHT] PENDING: '{description}'. Executing in {delay_seconds}s.",
                "OVERSIGHT",
            )
            timer = threading.Timer(
                delay_seconds,
                self._execute_wrapper,
                args=[action_id, description, payload],
            )
            self.pending_actions[action_id] = timer
            timer.start()

    def _execute_wrapper(
        self,
        action_id: str,
        description: str,
        payload: Callable[[], None],
    ) -> None:
        with self.lock:
            if action_id not in self.pending_actions:
                return
            self.pending_actions.pop(action_id, None)
        try:
            self.output_callback(
                f"[OVERSIGHT] TIMEOUT -> AUTO-EXECUTING: {description}",
                "OVERSIGHT",
            )
            payload()
        except Exception as exc:
            logging.exception(f"Execution failed for {action_id}: {exc}")

    def veto_action(self, action_id: str, user_reason: str) -> bool:
        with self.lock:
            timer = self.pending_actions.get(action_id)
            if not timer:
                return False
            timer.cancel()
            self.pending_actions.pop(action_id, None)
        self.output_callback(
            f"[OVERSIGHT] VETOED: {action_id} by Operator. Reason: {user_reason}",
            "OVERSIGHT",
        )
        return True


class SecurityNode:
    def __init__(self) -> None:
        self.db = PersistenceManager(DB_FILENAME)
        self.oversight = OversightEngine(output_callback=self._log_event)
        self._log_event("System Initialization. Database Connected.", "SYSTEM")

    def _log_event(self, message: str, module: str = "SYSTEM") -> None:
        logging.info(f"[{module}] {message}")
        self.db.log_event("INFO", module, message)

    def trigger_threat_response(self, ip_source: str, threat_type: str) -> None:
        self._log_event(
            f"Threat Detected: {threat_type} from {ip_source}",
            "THREAT_INT",
        )
        IntegrationHub.send_alert(
            f"High Severity Threat: {threat_type} ({ip_source})",
            "High",
        )
        action_id = f"BLOCK-{ip_source.replace('.', '-')}"
        description = f"Firewall Ban for {ip_source}"
        self.oversight.schedule_action(
            action_id=action_id,
            description=description,
            delay_seconds=10,
            payload=lambda: IntegrationHub.execute_firewall_block(ip_source),
        )


if __name__ == "__main__":
    nexus = SecurityNode()
    print("\n--- SIMULATION START: PERSISTENCE & INTEGRATION CHECK ---")
    nexus.trigger_threat_response("203.0.113.88", "SQL Injection Attempt")
    time.sleep(12)
    nexus.trigger_threat_response("198.51.100.22", "RDP Brute Force")
    time.sleep(2)
    print(">> OPERATOR INTERVENTION DETECTED")
    nexus.oversight.veto_action("BLOCK-198-51-100-22", "Authorized Vendor Access")
    print("\n--- DB AUDIT: VERIFYING PERSISTENCE ---")
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, module, message FROM event_logs ORDER BY id DESC LIMIT 5"
    )
    rows = cursor.fetchall()
    for row in rows:
        print(f"[DB_READ] {row}")
    conn.close()
    print("\nSystem ready for deployment.")
