"""
AEGIS-43: Intelligent Log Triage & Response Orchestrator

Refined prototype with:
- 3 deployment modes (SHADOW, HUMAN_GATED, AUTONOMOUS_VETO)
- Structured anomaly records for Watchtower modules
- Time-delayed veto Oversight Engine
- SQLite-backed immutable-ish audit log (append-only events)

This module is intended as a foundation for a real SOC-facing service.
"""

from __future__ import annotations

import datetime
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
AUDIT_DB_PATH = Path("aegis43_audit.db")

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


@dataclass
class AnomalyRecord:
    module_id: str
    description: str
    severity: RiskLevel
    detected_at: datetime.datetime
    metadata: Dict[str, Any]


@dataclass
class PendingAction:
    action_id: str
    description: str
    created_at: datetime.datetime
    delay_seconds: int
    risk_level: RiskLevel
    payload: Callable[[], None]


# ---------------------------------------------------------------------------
# SQLite-backed Audit Logger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Append-only audit logger with a simple schema.

    This is not full chain-hashing yet, but the table is treated as write-only
    from the application perspective.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT
                );
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def append(
        self,
        event_type: EventType,
        module: str,
        message: str,
        context_json: Optional[str] = None,
    ) -> None:
        ts = datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z"
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (timestamp, system_id, event_type, module, message, context_json)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (ts, SYSTEM_ID, event_type.value, module, message, context_json),
            )


# ---------------------------------------------------------------------------
# Oversight Engine (Time-Delayed Veto)
# ---------------------------------------------------------------------------


class OversightEngine:
    """Manages the time-delayed veto workflow for high-confidence actions."""

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
            self._audit.append(EventType.ACTION_STAGE, "OVERSIGHT", msg, None)

            timer = threading.Timer(
                action.delay_seconds,
                self._execute_if_not_vetoed,
                args=[action.action_id],
            )
            self._pending_timers[action.action_id] = timer
            self._pending_actions[action.action_id] = action
            timer.start()

    def _execute_if_not_vetoed(self, action_id: str) -> None:
        with self._lock:
            action = self._pending_actions.get(action_id)
            if not action:
                # Vetoed or already processed
                return

            # Clean up timer entry
            self._pending_timers.pop(action_id, None)
            self._pending_actions.pop(action_id, None)

        msg = f"[TIMEOUT] Auto-approving: {action.description}"
        logging.info(f"[OVERSIGHT] {msg}")
        self._audit.append(EventType.ACTION_EXECUTE, "OVERSIGHT", msg, None)

        try:
            action.payload()
            self._notify_callback(f"Action '{action.description}' EXECUTED successfully.")
        except Exception as exc:  # pragma: no cover - defensive
            err_msg = f"Execution failed for {action.action_id}: {exc}"
            logging.error(f"[OVERSIGHT] {err_msg}")
            self._audit.append(EventType.ERROR, "OVERSIGHT", err_msg, None)

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> None:
        with self._lock:
            timer = self._pending_timers.pop(action_id, None)
            action = self._pending_actions.pop(action_id, None)

        if not action or not timer:
            logging.warning(f"[OVERSIGHT] Cannot veto {action_id}: not pending.")
            return

        timer.cancel()
        msg = f"[VETOED] {action.description} | Operator={operator_id} | Reason={reason}"
        logging.warning(f"[OVERSIGHT] {msg}")
        self._audit.append(EventType.ACTION_VETO, "OVERSIGHT", msg, None)
        self._notify_callback(f"Action {action_id} vetoed by {operator_id}.")

    def snapshot_pending(self) -> List[PendingAction]:
        with self._lock:
            return list(self._pending_actions.values())


# ---------------------------------------------------------------------------
# Watchtower Modules
# ---------------------------------------------------------------------------


class WatchtowerConfig:
    """Configuration container for a single surveillance module."""

    def __init__(self, module_id: str, description: str, enabled: bool = True, sensitivity: float = 1.0):
        self.module_id = module_id
        self.description = description
        self.enabled = enabled
        self.sensitivity = sensitivity  # 0.1 (Lazy) to 2.0 (Paranoid)
        self.last_scan: Optional[datetime.datetime] = None


class WatchtowerManager:
    """Manages discrete surveillance modules.

    Naming is intentionally boring and enterprise-safe.
    """

    def __init__(self, audit: AuditLogger):
        self._audit = audit
        self.modules: Dict[str, WatchtowerConfig] = {}
        self._init_standard_modules()

    def _init_standard_modules(self) -> None:
        self.modules["WT_01_RES_MON"] = WatchtowerConfig(
            "WT_01_RES_MON", "System Resource Allocation Monitor"
        )
        self.modules["WT_02_NET_ING"] = WatchtowerConfig(
            "WT_02_NET_ING", "Network Ingress/Egress Traffic Analysis"
        )
        self.modules["WT_03_IAM_AUD"] = WatchtowerConfig(
            "WT_03_IAM_AUD", "Identity Access Management Audit Logger"
        )
        self.modules["WT_04_INT_VER"] = WatchtowerConfig(
            "WT_04_INT_VER", "File System Integrity Verification Service"
        )
        self.modules["WT_05_API_LAT"] = WatchtowerConfig(
            "WT_05_API_LAT", "External API Latency Observer"
        )
        self.modules["WT_06_DB_TXN"] = WatchtowerConfig(
            "WT_06_DB_TXN", "Database Transaction Consistency Manager"
        )
        self.modules["WT_07_CNF_MGT"] = WatchtowerConfig(
            "WT_07_CNF_MGT", "Endpoint Configuration Drift Detector"
        )
        self.modules["WT_08_REG_CMP"] = WatchtowerConfig(
            "WT_08_REG_CMP", "Regulatory Compliance Reporting Agent"
        )

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
        self._audit.append(EventType.CONFIG, "WATCHTOWER", msg, None)

    def perform_scan(self) -> List[AnomalyRecord]:
        """Iterates through enabled modules and emits structured anomalies.

        Still uses synthetic logic; replace with real metrics in production.
        """

        import random  # Local import to keep module import cost low

        logging.info("[WATCHTOWER] Initiating scan cycle...")
        anomalies: List[AnomalyRecord] = []

        for module_id, mod in self.modules.items():
            if not mod.enabled:
                continue

            now = datetime.datetime.utcnow()
            mod.last_scan = now

            # Synthetic anomaly probability scaled by sensitivity
            risk_factor = random.random()
            threshold = 0.1 * mod.sensitivity
            if risk_factor < threshold:
                severity = RiskLevel.HIGH if mod.sensitivity >= 1.5 else RiskLevel.MEDIUM
                desc = f"Anomaly detected in {mod.description} (risk_factor={risk_factor:.3f})"
                anomalies.append(
                    AnomalyRecord(
                        module_id=module_id,
                        description=desc,
                        severity=severity,
                        detected_at=now,
                        metadata={"risk_factor": risk_factor, "threshold": threshold},
                    )
                )

        logging.info(f"[WATCHTOWER] Scan complete. {len(anomalies)} anomalies flagged.")
        return anomalies


# ---------------------------------------------------------------------------
# Security Node (Core Orchestrator)
# ---------------------------------------------------------------------------


class SecurityNode:
    def __init__(self, mode: DeploymentMode = DeploymentMode.SHADOW):
        self._lock = threading.RLock()
        self.mode = mode

        self.audit = AuditLogger(AUDIT_DB_PATH)
        self.oversight = OversightEngine(self.audit, notify_callback=self._notify_operator)
        self.watchtowers = WatchtowerManager(self.audit)

        self._event_buffer: List[Dict[str, Any]] = []

        self._log(EventType.SYSTEM, "SYSTEM", f"[{SYSTEM_ID}] Initialization complete.")
        self._log(EventType.SYSTEM, "SYSTEM", f"[{SYSTEM_ID}] Watchtower modules loaded: {len(self.watchtowers.modules)}")
        self._log(EventType.SYSTEM, "SYSTEM", f"Deployment mode: {self.mode.name}")

    # ---------------------------- Core Logging ----------------------------

    def _log(self, event_type: EventType, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        context_json = None
        if context is not None:
            import json

            context_json = json.dumps(context, default=str)

        with self._lock:
            self.audit.append(event_type, module, message, context_json)
            self._event_buffer.append(
                {
                    "timestamp": datetime.datetime.utcnow(),
                    "event_type": event_type.value,
                    "module": module,
                    "message": message,
                    "context": context,
                }
            )
        logging.info(f"[{module}] {message}")

    def _notify_operator(self, message: str) -> None:
        # Placeholder hook for UI / webhook layer
        self._log(EventType.SYSTEM, "NOTIFY", message)

    # ---------------------------- Actions ----------------------------

    def _execute_quarantine_target(self, target: str, context: Dict[str, Any]) -> None:
        msg = f"Target '{target}' isolated via firewall / IAM ruleset."
        self._log(EventType.ACTION_EXECUTE, "DEFENSE_ACT", msg, context)

    # ------------------------- Public Operations -------------------------

    def run_watchtower_cycle(self) -> None:
        anomalies = self.watchtowers.perform_scan()
        for anomaly in anomalies:
            self._handle_anomaly(anomaly)

    def _handle_anomaly(self, anomaly: AnomalyRecord) -> None:
        self._log(
            EventType.ALERT,
            "ALERT",
            f"[{anomaly.module_id}] {anomaly.description}",
            context={"severity": anomaly.severity.value, **anomaly.metadata},
        )

        # Example rule: IAM anomalies escalate to access revocation suggestion
        if anomaly.module_id == "WT_03_IAM_AUD":
            principal = anomaly.metadata.get("principal_id", "Unknown.Principal")
            reason = "Suspicious IAM access pattern"
            self.trigger_response(principal, reason, anomaly.severity)

    def trigger_response(
        self,
        principal_id: str,
        reason: str,
        severity: RiskLevel,
    ) -> None:
        """Triggers a response according to deployment mode.

        In SHADOW mode: log the hypothetical action.
        In HUMAN_GATED mode: stage action, require explicit approval.
        In AUTONOMOUS_VETO mode: schedule vetoable action.
        """

        action_id = f"REVOKE-{principal_id.replace('.', '-')}-{int(time.time())}"
        description = f"Revoke access for {principal_id} ({reason})"
        context = {"principal_id": principal_id, "reason": reason, "severity": severity.value}

        if self.mode == DeploymentMode.SHADOW:
            msg = f"[SHADOW] Would perform action {action_id}: {description}"
            self._log(EventType.ACTION_STAGE, "ADVISORY", msg, context)
            return

        if self.mode == DeploymentMode.HUMAN_GATED:
            msg = f"[HUMAN_GATED] Staged action {action_id}: {description}. Awaiting operator approval."
            self._log(EventType.ACTION_STAGE, "ADVISORY", msg, context)
            # In a real system, this would be exposed via an API/UI for explicit approval
            return

        if self.mode == DeploymentMode.AUTONOMOUS_VETO:
            pending = PendingAction(
                action_id=action_id,
                description=description,
                created_at=datetime.datetime.utcnow(),
                delay_seconds=self._resolve_delay_for_severity(severity),
                risk_level=severity,
                payload=lambda: self._execute_quarantine_target(principal_id, context),
            )
            self.oversight.schedule_vetoable_action(pending)

    def approve_staged_action(self, action_id: str, operator_id: str) -> None:
        """Placeholder for HUMAN_GATED mode approval.

        This method would look up a staged action from persistent storage
        and execute it. For now, it is a stub to sketch the interface.
        """
        msg = f"[APPROVE_STUB] Operator={operator_id} requested approval for {action_id}."
        self._log(EventType.ACTION_EXECUTE, "ADVISORY", msg)
        # TODO: attach to real staged action store

    @staticmethod
    def _resolve_delay_for_severity(severity: RiskLevel) -> int:
        if severity is RiskLevel.HIGH:
            return 10
        if severity is RiskLevel.MEDIUM:
            return 30
        return 60


# ---------------------------------------------------------------------------
# Simple Demo Harness
# ---------------------------------------------------------------------------


def _demo() -> None:
    node = SecurityNode(mode=DeploymentMode.AUTONOMOUS_VETO)

    # Example tuning
    node.watchtowers.configure_module("WT_02_NET_ING", sensitivity=1.5)
    node.watchtowers.configure_module("WT_03_IAM_AUD", sensitivity=2.0)
    node.watchtowers.configure_module("WT_08_REG_CMP", enabled=False)

    for i in range(3):
        logging.info(f"\n[Cycle {i+1}] Running watchtower diagnostics...")
        node.run_watchtower_cycle()
        time.sleep(1)

    pending = node.oversight.snapshot_pending()
    logging.info(f"\nPending vetoable actions: {len(pending)}")
    if pending:
        for p in pending:
            logging.info(f" - {p.action_id}: {p.description} (Risk={p.risk_level.value})")
        # Let them auto-execute for demo
        time.sleep(65)


if __name__ == "__main__":
    _demo()
