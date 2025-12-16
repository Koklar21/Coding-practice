"""
AEGIS Nexus: Persistence & Integration Node (Main File) - Hardened

- DB stored next to this file (safe default)
- SQLite directory creation
- Journal mode defaults to DELETE; can be WAL if stable
- Oversight timers are daemon threads
- Data Vault entries are hash-chained (tamper-evident) with deterministic ordering
- Replay defense + action budgeting + corroboration (two-signal) built in
- No demo / no side effects on import
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

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

# -------------------------
# Config (tunable knobs)
# -------------------------
REPLAY_TTL_SECONDS = 3600                 # suppress duplicates for 1 hour
MAX_PENDING_ACTIONS = 250                 # prevent timer pileups
BUDGET_WINDOW_SECONDS = 300               # 5 min window
BUDGET_MAX_ACTIONS_PER_IP = 5             # per-ip action spam ceiling
CORROBORATION_TTL_SECONDS = 600           # 10 minutes
REQUIRE_TWO_SIGNALS_FOR_HIGH = True       # stops one-signal nukes
MAX_CONTEXT_JSON = 20_000                 # prevent JSON bombs


def _utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(tzinfo=None)


def _iso_utc(dt: datetime.datetime, *, seconds: bool = False) -> str:
    if seconds:
        return dt.isoformat(timespec="seconds") + "Z"
    return dt.isoformat(timespec="microseconds") + "Z"


def _canonical_json(obj: dict, *, max_len: int = MAX_CONTEXT_JSON) -> str:
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    if len(s) > max_len:
        raise ValueError(f"context_json too large ({len(s)} > {max_len})")
    return s


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_obj(obj: dict) -> str:
    return _sha256_hex(_canonical_json(obj).encode("utf-8"))


@dataclass(frozen=True)
class ThreatEvent:
    event_id: str
    ip: str
    threat_type: str
    severity: str  # LOW/MEDIUM/HIGH
    observed_at: datetime.datetime
    evidence: dict


class PersistenceManager:
    """
    SQLite persistence layer:
      - event_logs: operational event stream
      - data_vault: write-once-ish vault with hash chaining for tamper evidence
      - seen_events: replay defense
      - action_budget: per-ip action budget
      - corroboration: two-signal confirmation cache
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
        # check_same_thread=False because we use per-call connections across threads
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
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

            # data_vault: deterministic chain ordering uses vault_seq
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS data_vault (
                    vault_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT UNIQUE NOT NULL,
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_ts ON data_vault(timestamp);")

            # replay defense
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_events (
                    event_id TEXT PRIMARY KEY,
                    first_seen_at TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    severity TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_seen_first ON seen_events(first_seen_at);")

            # action budget
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS action_budget (
                    ip TEXT PRIMARY KEY,
                    window_start TEXT NOT NULL,
                    used_count INTEGER NOT NULL
                );
                """
            )

            # corroboration (two-signal)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS corroboration (
                    key TEXT PRIMARY KEY,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    count INTEGER NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_last ON corroboration(last_seen_at);")

    def log_event(self, level: str, module: str, message: str, context: Optional[dict] = None) -> None:
        ts = _iso_utc(_utcnow())
        ctx = _canonical_json(context) if context is not None else None
        with self.lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO event_logs (timestamp, level, module, message, context_json)
                VALUES (?, ?, ?, ?, ?);
                """,
                (ts, level, module, message, ctx),
            )

    # ---------------------- Vault (hash-chained) ----------------------

    def _get_last_vault_hash(self, conn: sqlite3.Connection) -> Optional[str]:
        row = conn.execute("SELECT record_hash FROM data_vault ORDER BY vault_seq DESC LIMIT 1;").fetchone()
        return row[0] if row else None

    def vault_store(self, record_id: str, label: str, payload: dict) -> None:
        payload_json = _canonical_json(payload)
        payload_sha = _sha256_hex(payload_json.encode("utf-8"))
        ts = _iso_utc(_utcnow())

        with self.lock, self._get_conn() as conn:
            prev_hash = self._get_last_vault_hash(conn)
            record_blob = _canonical_json(
                {
                    "record_id": record_id,
                    "timestamp": ts,
                    "label": label,
                    "payload_sha256": payload_sha,
                    "prev_hash": prev_hash,
                }
            ).encode("utf-8")
            record_hash = _sha256_hex(record_blob)

            conn.execute(
                """
                INSERT INTO data_vault (record_id, timestamp, label, payload_json, payload_sha256, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (record_id, ts, label, payload_json, payload_sha, prev_hash, record_hash),
            )

    def verify_vault_chain(self) -> bool:
        """Verifies hash chaining integrity across data_vault deterministically."""
        with self.lock, self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT vault_seq, record_id, timestamp, label, payload_sha256, prev_hash, record_hash
                FROM data_vault ORDER BY vault_seq ASC;
                """
            ).fetchall()

        prev = None
        for _seq, record_id, ts, label, payload_sha, prev_hash, record_hash in rows:
            if prev_hash != prev:
                logging.error(f"[VAULT_VERIFY] Chain break at {record_id}: prev_hash mismatch.")
                return False

            blob = _canonical_json(
                {
                    "record_id": record_id,
                    "timestamp": ts,
                    "label": label,
                    "payload_sha256": payload_sha,
                    "prev_hash": prev_hash,
                }
            ).encode("utf-8")
            expected = _sha256_hex(blob)
            if expected != record_hash:
                logging.error(f"[VAULT_VERIFY] Hash mismatch at {record_id}.")
                return False

            prev = record_hash

        logging.info("[VAULT_VERIFY] Vault chain OK.")
        return True

    # ---------------------- Replay defense ----------------------

    def record_event_if_new(self, event: ThreatEvent, *, ttl_seconds: int = REPLAY_TTL_SECONDS) -> bool:
        """
        Returns True if event is new; False if duplicate (suppressed).
        TTL cleanup happens opportunistically to bound growth.
        """
        now = _utcnow()
        cutoff = now - datetime.timedelta(seconds=ttl_seconds)

        with self.lock, self._get_conn() as conn:
            conn.execute("DELETE FROM seen_events WHERE first_seen_at < ?;", (_iso_utc(cutoff, seconds=True),))

            try:
                conn.execute(
                    "INSERT INTO seen_events(event_id, first_seen_at, ip, severity) VALUES (?, ?, ?, ?);",
                    (event.event_id, _iso_utc(now, seconds=True), event.ip, event.severity),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    # ---------------------- Action budget ----------------------

    def consume_budget(self, ip: str, *, window_seconds: int = BUDGET_WINDOW_SECONDS, max_actions: int = BUDGET_MAX_ACTIONS_PER_IP) -> bool:
        now = _utcnow()
        window_start = _iso_utc(now.replace(microsecond=0), seconds=True)

        with self.lock, self._get_conn() as conn:
            row = conn.execute("SELECT window_start, used_count FROM action_budget WHERE ip = ?;", (ip,)).fetchone()
            if not row:
                conn.execute("INSERT INTO action_budget(ip, window_start, used_count) VALUES (?, ?, ?);", (ip, window_start, 1))
                return True

            prev_start = datetime.datetime.fromisoformat(row[0].replace("Z", ""))
            used = int(row[1])

            if (now - prev_start).total_seconds() > window_seconds:
                conn.execute("UPDATE action_budget SET window_start = ?, used_count = ? WHERE ip = ?;", (window_start, 1, ip))
                return True

            if used >= max_actions:
                return False

            conn.execute("UPDATE action_budget SET used_count = used_count + 1 WHERE ip = ?;", (ip,))
            return True

    # ---------------------- Corroboration ----------------------

    def corroboration_bump(self, key: str, *, ttl_seconds: int = CORROBORATION_TTL_SECONDS) -> int:
        now = _utcnow()
        cutoff = now - datetime.timedelta(seconds=ttl_seconds)

        with self.lock, self._get_conn() as conn:
            conn.execute("DELETE FROM corroboration WHERE last_seen_at < ?;", (_iso_utc(cutoff, seconds=True),))
            row = conn.execute("SELECT count FROM corroboration WHERE key = ?;", (key,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO corroboration(key, first_seen_at, last_seen_at, count) VALUES (?, ?, ?, ?);",
                    (key, _iso_utc(now, seconds=True), _iso_utc(now, seconds=True), 1),
                )
                return 1

            conn.execute(
                "UPDATE corroboration SET last_seen_at = ?, count = count + 1 WHERE key = ?;",
                (_iso_utc(now, seconds=True), key),
            )
            return int(row[0]) + 1


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
    """Time-delayed execution with operator veto. Hardened to resist floods."""

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
            if len(self.pending_actions) >= MAX_PENDING_ACTIONS:
                self.output_callback("[OVERSIGHT] Back-pressure: too many pending actions. Dropping request.", "OVERSIGHT", context)
                return

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

    def _execute_wrapper(self, action_id: str, description: str, payload: Callable[[], None], context: Optional[dict]) -> None:
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
        user_reason = (user_reason or "").strip()[:300]
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
        try:
            self.db.log_event("INFO", module, message, context)
        except Exception as exc:
            logging.error(f"[DB_LOG_FAIL] {exc}")

    def trigger_threat_response(self, ip_source: str, threat_type: str, *, severity: str = "HIGH") -> str:
        ip_source = (ip_source or "").strip()
        threat_type = (threat_type or "UNKNOWN").strip()
        now = _utcnow()

        # deterministic-ish event id: you should supply a real one from upstream telemetry in production
        event_obj = {
            "ip": ip_source,
            "threat_type": threat_type,
            "severity": severity,
            "observed_at": _iso_utc(now, seconds=True),
        }
        event_id = _hash_obj(event_obj)

        evt = ThreatEvent(
            event_id=event_id,
            ip=ip_source,
            threat_type=threat_type,
            severity=severity,
            observed_at=now,
            evidence={"source": "SecurityNexus", **event_obj},
        )

        # replay defense first
        if not self.db.record_event_if_new(evt):
            self._log_event("Duplicate threat event suppressed (replay defense).", "THREAT_INT", {"event_id": event_id, **event_obj})
            return f"REPLAY-SUPPRESSED-{event_id[:12]}"

        context = {"event_id": event_id, "ip": ip_source, "threat_type": threat_type, "severity": severity}
        self._log_event(f"Threat Detected: {threat_type} from {ip_source}", "THREAT_INT", context)

        IntegrationHub.send_alert(f"Threat: {threat_type} ({ip_source})", severity)

        # two-signal rule for HIGH (optional)
        if severity.upper() == "HIGH" and REQUIRE_TWO_SIGNALS_FOR_HIGH:
            corr_key = f"HIGH:{ip_source}:{threat_type}"
            count = self.db.corroboration_bump(corr_key)
            self._log_event("Corroboration bump.", "THREAT_INT", {**context, "corr_key": corr_key, "count": count})
            if count < 2:
                self._log_event("Waiting for second signal before scheduling hard action.", "THREAT_INT", context)
                return f"CORR-WAIT-{event_id[:12]}"

        # budget check (prevents baiting)
        if not self.db.consume_budget(ip_source):
            self._log_event("Action budget exceeded for IP. Suppressing firewall block.", "THREAT_INT", context)
            return f"BUDGET-DENY-{event_id[:12]}"

        action_id = f"BLOCK-{ip_source.replace('.', '-')}-{int(time.time() // 30)}"
        description = f"Firewall Ban for {ip_source}"

        # Store decision intent in vault (governance-friendly)
        vault_id = f"DECISION-{action_id}-{int(now.timestamp())}"
        self.db.vault_store(vault_id, "threat_response_intent", {"action_id": action_id, "description": description, **context})

        self.oversight.schedule_action(
            action_id=action_id,
            description=description,
            delay_seconds=10,
            payload=lambda: IntegrationHub.execute_firewall_block(ip_source),
            context=context,
        )
        return action_id