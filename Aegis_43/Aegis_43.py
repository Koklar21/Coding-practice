"""
AEGIS-43: Intelligent Log Triage & Response Orchestrator (No Demo)

- 3 deployment modes: SHADOW, HUMAN_GATED, AUTONOMOUS_VETO
- Structured anomaly records for Watchtower modules
- Time-delayed veto Oversight Engine (daemon timers so process exits cleanly)
- SQLite-backed tamper-evident audit log (hash-chained)
- HUMAN_GATED staged actions persisted in SQLite
- No demo harness, no auto-running logic

This is a foundation for a SOC-facing service. Add FastAPI/UI on top.
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
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(module)-18s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

SYSTEM_ID = "AEGIS-43-NODE-01"


# ---------------------------------------------------------------------------
# Enums & Data Models
# ---------------------------------------------------------------------------


class DeploymentMode(Enum):
    SHADOW = auto()           # Log-only, no actions executed
    HUMAN_GATED = auto()      # Actions staged, require explicit approval
    AUTONOMOUS_VETO = auto()  # Actions execute after delay unless vetoed


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EventType(Enum):
    SYSTEM = "SYSTEM"
    ALERT = "ALERT"
    ACTION_STAGE = "ACTION_STAGE"
    ACTION_EXECUTE = "ACTION_EXECUTE"
    ACTION_VETO = "ACTION_VETO"
    CONFIG = "CONFIG"
    ERROR = "ERROR"


@dataclass(frozen=True)
class AnomalyRecord:
    module_id: str
    description: str
    severity: RiskLevel
    detected_at: datetime.datetime
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    description: str
    created_at: datetime.datetime
    delay_seconds: int
    risk_level: RiskLevel
    payload: Callable[[], None]


# ---------------------------------------------------------------------------
# SQLite-backed Audit Logger (hash-chained)
# ---------------------------------------------------------------------------


class AuditLogger:
    """
    Append-only audit logger with tamper-evident hashing.

    Notes:
    - SQLite does NOT create directories, so we do.
    - WAL can be flaky in some sandbox/mobile environments. Default is DELETE.
    """

    def __init__(self, db_path: Path, *, journal_mode: str = "DELETE"):
        self.db_path = Path(db_path)
        self.journal_mode = journal_mode
        self._lock = threading.RLock()
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
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT,
                    prev_hash TEXT,
                    event_hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp);"
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS staged_actions (
                    action_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    status TEXT NOT NULL,   -- STAGED | APPROVED | EXECUTED | REJECTED
                    operator_id TEXT,
                    decided_at TEXT
                );
                """
            )

    @staticmethod
    def _hash_event(
        *,
        timestamp: str,
        system_id: str,
        event_type: str,
        module: str,
        message: str,
        context_json: Optional[str],
        prev_hash: Optional[str],
    ) -> str:
        payload = {
            "timestamp": timestamp,
            "system_id": system_id,
            "event_type": event_type,
            "module": module,
            "message": message,
            "context_json": context_json,
            "prev_hash": prev_hash,
        }
        blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _get_last_hash(self, conn: sqlite3.Connection) -> Optional[str]:
        row = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;"
        ).fetchone()
        return row[0] if row else None

    def append(
        self,
        event_type: EventType,
        module: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        ts = datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z"
        context_json = json.dumps(context, default=str) if context is not None else None

        with self._lock, self._get_conn() as conn:
            prev_hash = self._get_last_hash(conn)
            event_hash = self._hash_event(
                timestamp=ts,
                system_id=SYSTEM_ID,
                event_type=event_type.value,
                module=module,
                message=message,
                context_json=context_json,
                prev_hash=prev_hash,
            )
            conn.execute(
                """
                INSERT INTO audit_events
                (timestamp, system_id, event_type, module, message, context_json, prev_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (ts, SYSTEM_ID, event_type.value, module, message, context_json, prev_hash, event_hash),
            )

    # -------------------- Staged action persistence (HUMAN_GATED) --------------------

    def stage_action(
        self,
        action_id: str,
        description: str,
        severity: RiskLevel,
        context: Dict[str, Any],
    ) -> None:
        created_at = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO staged_actions
                (action_id, created_at, description, severity, context_json, status)
                VALUES (?, ?, ?, ?, ?, 'STAGED');
                """,
                (action_id, created_at, description, severity.value, json.dumps(context, default=str)),
            )

    def get_staged_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT action_id, created_at, description, severity, context_json, status
                FROM staged_actions WHERE action_id = ?;
                """,
                (action_id,),
            ).fetchone()

        if not row:
            return None

        return {
            "action_id": row[0],
            "created_at": row[1],
            "description": row[2],
            "severity": row[3],
            "context": json.loads(row[4]),
            "status": row[5],
        }

    def mark_action_decision(self, action_id: str, *, status: str, operator_id: str) -> None:
        decided_at = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                UPDATE staged_actions
                SET status = ?, operator_id = ?, decided_at = ?
                WHERE action_id = ?;
                """,
                (status, operator_id, decided_at, action_id),
            )


# ---------------------------------------------------------------------------
# Oversight Engine (Time-Delayed Veto)
# ---------------------------------------------------------------------------


class OversightEngine:
    """Manages time-delayed veto workflow for actions."""

    def __init__(self, audit: AuditLogger, notify_callback: Callable[[str], None]):
        self._audit = audit
        self._notify_callback = notify_callback
        self._lock = threading.RLock()
        self._pending_timers: Dict[str, threading.Timer] = {}
        self._pending_actions: Dict[str, PendingAction] = {}

    def schedule_vetoable_action(self, action: PendingAction) -> None:
        with self._lock:
            if action.action_id in self._pending_timers:
                logging.warning(f"[OVERSIGHT] Action {action.action_id} already pending.")
                return

            msg = (
                f"[PENDING] {action.description} | Risk={action.risk_level.value} | "
                f"Exec in {action.delay_seconds}s unless vetoed."
            )
            logging.info(f"[OVERSIGHT] {msg}")
            self._audit.append(EventType.ACTION_STAGE, "OVERSIGHT", msg)

            timer = threading.Timer(
                action.delay_seconds,
                self._execute_if_not_vetoed,
                args=[action.action_id],
            )
            timer.daemon = True  # don’t keep the process alive
            self._pending_timers[action.action_id] = timer
            self._pending_actions[action.action_id] = action
            timer.start()

    def _execute_if_not_vetoed(self, action_id: str) -> None:
        with self._lock:
            action = self._pending_actions.get(action_id)
            if not action:
                return
            self._pending_timers.pop(action_id, None)
            self._pending_actions.pop(action_id, None)

        msg = f"[TIMEOUT] Auto-approving: {action.description}"
        logging.info(f"[OVERSIGHT] {msg}")
        self._audit.append(EventType.ACTION_EXECUTE, "OVERSIGHT", msg)

        try:
            action.payload()
            self._notify_callback(f"Action '{action.description}' EXECUTED successfully.")
        except Exception as exc:
            err_msg = f"Execution failed for {action.action_id}: {exc}"
            logging.error(f"[OVERSIGHT] {err_msg}")
            self._audit.append(EventType.ERROR, "OVERSIGHT", err_msg)

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> bool:
        with self._lock:
            timer = self._pending_timers.pop(action_id, None)
            action = self._pending_actions.pop(action_id, None)

        if not action or not timer:
            logging.warning(f"[OVERSIGHT] Cannot veto {action_id}: not pending.")
            return False

        timer.cancel()
        msg = f"[VETOED] {action.description} | Operator={operator_id} | Reason={reason}"
        logging.warning(f"[OVERSIGHT] {msg}")
        self._audit.append(EventType.ACTION_VETO, "OVERSIGHT", msg)
        self._notify_callback(f"Action {action_id} vetoed by {operator_id}.")
        return True

    def snapshot_pending(self) -> List[PendingAction]:
        with self._lock:
            return list(self._pending_actions.values())


# ---------------------------------------------------------------------------
# Watchtower Modules
# ---------------------------------------------------------------------------


class WatchtowerConfig:
    def __init__(self, module_id: str, description: str, enabled: bool = True, sensitivity: float = 1.0):
        self.module_id = module_id
        self.description = description
        self.enabled = enabled
        self.sensitivity = sensitivity
        self.last_scan: Optional[datetime.datetime] = None


class WatchtowerManager:
    """Manages discrete surveillance modules."""

    def __init__(self, audit: AuditLogger):
        self._audit = audit
        self.modules: Dict[str, WatchtowerConfig] = {}
        self._init_standard_modules()

    def _init_standard_modules(self) -> None:
        self.modules["WT_01_RES_MON"] = WatchtowerConfig("WT_01_RES_MON", "System Resource Allocation Monitor")
        self.modules["WT_02_NET_ING"] = WatchtowerConfig("WT_02_NET_ING", "Network Ingress/Egress Traffic Analysis")
        self.modules["WT_03_IAM_AUD"] = WatchtowerConfig("WT_03_IAM_AUD", "Identity Access Management Audit Logger")
        self.modules["WT_04_INT_VER"] = WatchtowerConfig("WT_04_INT_VER", "File System Integrity Verification Service")
        self.modules["WT_05_API_LAT"] = WatchtowerConfig("WT_05_API_LAT", "External API Latency Observer")
        self.modules["WT_06_DB_TXN"] = WatchtowerConfig("WT_06_DB_TXN", "Database Transaction Consistency Manager")
        self.modules["WT_07_CNF_MGT"] = WatchtowerConfig("WT_07_CNF_MGT", "Endpoint Configuration Drift Detector")
        self.modules["WT_08_REG_CMP"] = WatchtowerConfig("WT_08_REG_CMP", "Regulatory Compliance Reporting Agent")

    def configure_module(
        self,
        module_id: str,
        *,
        enabled: Optional[bool] = None,
        sensitivity: Optional[float] = None,
    ) -> None:
        mod = self.modules.get(module_id)
        if not mod:
            logging.error(f"[CONFIG] Module {module_id} not found.")
            return

        if enabled is not None:
            mod.enabled = enabled
        if sensitivity is not None:
            mod.sensitivity = sensitivity

        msg = f"Updated {module_id}: enabled={mod.enabled}, sensitivity={mod.sensitivity}"
        logging.info(f"[CONFIG] {msg}")
        self._audit.append(EventType.CONFIG, "WATCHTOWER", msg)

    def perform_scan(self) -> List[AnomalyRecord]:
        """
        Iterates through enabled modules and emits structured anomalies.

        Still synthetic. Replace metadata generation with real telemetry in production.
        """
        import random

        anomalies: List[AnomalyRecord] = []
        now = datetime.datetime.utcnow()

        for module_id, mod in self.modules.items():
            if not mod.enabled:
                continue

            mod.last_scan = now

            risk_factor = random.random()
            threshold = 0.1 * mod.sensitivity

            if risk_factor < threshold:
                severity = RiskLevel.HIGH if mod.sensitivity >= 1.5 else RiskLevel.MEDIUM
                desc = f"Anomaly detected in {mod.description} (risk_factor={risk_factor:.3f})"

                meta: Dict[str, Any] = {"risk_factor": risk_factor, "threshold": threshold}

                # IAM module emits a principal_id so response rules can fire.
                if module_id == "WT_03_IAM_AUD":
                    meta["principal_id"] = random.choice(
                        ["svc.billing", "svc.payments", "devops.oncall", "Unknown.Principal"]
                    )

                anomalies.append(
                    AnomalyRecord(
                        module_id=module_id,
                        description=desc,
                        severity=severity,
                        detected_at=now,
                        metadata=meta,
                    )
                )

        return anomalies


# ---------------------------------------------------------------------------
# Security Node (Core Orchestrator)
# ---------------------------------------------------------------------------


class SecurityNode:
    def __init__(
        self,
        *,
        mode: DeploymentMode = DeploymentMode.SHADOW,
        audit_db_path: Optional[Path] = None,
        journal_mode: str = "DELETE",
    ):
        self._lock = threading.RLock()
        self.mode = mode

        # Safe default path: DB next to this file (or current working dir if __file__ missing)
        if audit_db_path is None:
            try:
                base = Path(__file__).resolve().parent
            except NameError:
                base = Path.cwd()
            audit_db_path = base / "aegis43_audit.db"

        self.audit = AuditLogger(audit_db_path, journal_mode=journal_mode)
        self.oversight = OversightEngine(self.audit, notify_callback=self._notify_operator)
        self.watchtowers = WatchtowerManager(self.audit)

        self._log(EventType.SYSTEM, "SYSTEM", f"[{SYSTEM_ID}] Initialization complete.")
        self._log(EventType.SYSTEM, "SYSTEM", f"Watchtower modules loaded: {len(self.watchtowers.modules)}")
        self._log(EventType.SYSTEM, "SYSTEM", f"Deployment mode: {self.mode.name}")

    # ---------------------------- Logging ----------------------------

    def _log(
        self,
        event_type: EventType,
        module: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            self.audit.append(event_type, module, message, context)
        logging.info(f"[{module}] {message}")

    def _notify_operator(self, message: str) -> None:
        self._log(EventType.SYSTEM, "NOTIFY", message)

    # ---------------------------- Actions ----------------------------

    def _execute_quarantine_target(self, target: str, context: Dict[str, Any]) -> None:
        msg = f"Target '{target}' isolated via firewall / IAM ruleset."
        self._log(EventType.ACTION_EXECUTE, "DEFENSE_ACT", msg, context)

    # ------------------------- Public API -------------------------

    def run_watchtower_cycle(self) -> List[AnomalyRecord]:
        """Run a scan + handle anomalies according to rules. Returns anomalies for UI/API."""
        anomalies = self.watchtowers.perform_scan()
        for anomaly in anomalies:
            self._handle_anomaly(anomaly)
        return anomalies

    def ingest_anomaly(self, anomaly: AnomalyRecord) -> None:
        """Feed an externally-generated anomaly into the orchestrator."""
        self._handle_anomaly(anomaly)

    def list_pending_veto_actions(self) -> List[PendingAction]:
        return self.oversight.snapshot_pending()

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> bool:
        return self.oversight.veto_action(action_id, operator_id, reason)

    def list_modules(self) -> Dict[str, WatchtowerConfig]:
        return dict(self.watchtowers.modules)

    def configure_module(self, module_id: str, *, enabled: Optional[bool] = None, sensitivity: Optional[float] = None) -> None:
        self.watchtowers.configure_module(module_id, enabled=enabled, sensitivity=sensitivity)

    def trigger_response(self, principal_id: str, reason: str, severity: RiskLevel) -> str:
        """Triggers a response according to deployment mode. Returns action_id."""
        action_id = f"REVOKE-{principal_id.replace('.', '-')}-{int(time.time())}"
        description = f"Revoke access for {principal_id} ({reason})"
        context = {"principal_id": principal_id, "reason": reason, "severity": severity.value}

        if self.mode == DeploymentMode.SHADOW:
            self._log(EventType.ACTION_STAGE, "ADVISORY", f"[SHADOW] Would perform {action_id}: {description}", context)
            return action_id

        if self.mode == DeploymentMode.HUMAN_GATED:
            self.audit.stage_action(action_id, description, severity, context)
            self._log(EventType.ACTION_STAGE, "ADVISORY", f"[HUMAN_GATED] Staged {action_id}: {description}", context)
            return action_id

        # AUTONOMOUS_VETO
        pending = PendingAction(
            action_id=action_id,
            description=description,
            created_at=datetime.datetime.utcnow(),
            delay_seconds=self._resolve_delay_for_severity(severity),
            risk_level=severity,
            payload=lambda: self._execute_quarantine_target(principal_id, context),
        )
        self.oversight.schedule_vetoable_action(pending)
        return action_id

    def approve_staged_action(self, action_id: str, operator_id: str) -> bool:
        """Approve + execute a staged action (HUMAN_GATED). Returns success bool."""
        staged = self.audit.get_staged_action(action_id)
        if not staged or staged["status"] != "STAGED":
            self._log(EventType.ERROR, "ADVISORY", f"[APPROVE] {action_id} not found or not STAGED.")
            return False

        self.audit.mark_action_decision(action_id, status="APPROVED", operator_id=operator_id)
        self._log(EventType.ACTION_EXECUTE, "ADVISORY", f"[APPROVED] {action_id} by {operator_id}. Executing...")

        ctx = staged["context"]
        principal = str(ctx.get("principal_id", "Unknown.Principal"))
        self._execute_quarantine_target(principal, ctx)

        self.audit.mark_action_decision(action_id, status="EXECUTED", operator_id=operator_id)
        return True

    # ------------------------- Rules -------------------------

    def _handle_anomaly(self, anomaly: AnomalyRecord) -> None:
        self._log(
            EventType.ALERT,
            "ALERT",
            f"[{anomaly.module_id}] {anomaly.description}",
            context={"severity": anomaly.severity.value, **anomaly.metadata},
        )

        # Example rule: IAM anomalies escalate to access revocation suggestion
        if anomaly.module_id == "WT_03_IAM_AUD":
            principal = str(anomaly.metadata.get("principal_id", "Unknown.Principal"))
            reason = "Suspicious IAM access pattern"
            self.trigger_response(principal, reason, anomaly.severity)

    @staticmethod
    def _resolve_delay_for_severity(severity: RiskLevel) -> int:
        if severity is RiskLevel.HIGH:
            return 10
        if severity is RiskLevel.MEDIUM:
            return 30
        return 60