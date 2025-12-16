import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional, Tuple

SYSTEM_ID = "AEGIS-43-NEXUS-01"


class OpMode(Enum):
    SHADOW = "SHADOW_ADVISORY"
    HUMAN_GATED = "HUMAN_GATED"
    ACTIVE = "AUTONOMOUS_VETO"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s",
)


# ---------------------------------------------------------------------------
# Integration Hub (Execution Boundary)
# ---------------------------------------------------------------------------

class IntegrationHub:
    """All real-world effects terminate here. Keep this boring and auditable."""

    @staticmethod
    def execute_firewall_block(ip_address: str, *, reason: str, evidence: dict) -> bool:
        # Real implementation would call your firewall/IAM provider.
        logging.warning(f"[FIREWALL] HARD BLOCK applied to {ip_address} | reason={reason} | evidence={evidence}")
        return True

    @staticmethod
    def log_shadow_action(ip_address: str, *, reason: str, evidence: dict) -> bool:
        logging.info(f"[SHADOW] WOULD have blocked {ip_address} | reason={reason} | evidence={evidence}")
        return True


# ---------------------------------------------------------------------------
# Policy Objects (so you can tune behavior without rewiring logic)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    target: str  # e.g., IP
    description: str
    delay_seconds: int
    severity: str  # LOW/MEDIUM/HIGH (string to avoid dragging more enums in)
    reason: str
    evidence: dict
    real_payload: Callable[[], None]
    shadow_payload: Callable[[], None]


@dataclass
class BudgetState:
    window_start: float
    used: int


@dataclass
class CorroborationState:
    first_seen: float
    last_seen: float
    count: int


# ---------------------------------------------------------------------------
# Oversight Engine (Veto + Gating) - hardened
# ---------------------------------------------------------------------------

class OversightEngine:
    """
    Hardened execution boundary:
    - Idempotency window (prevents replay spam)
    - Action budgets per target (prevents baiting / runaway)
    - Two-signal confirmation (prevents one-signal nukes)
    - Bounded pending actions (prevents timer pileups)
    """

    def __init__(
        self,
        mode_resolver: Callable[[], OpMode],
        *,
        # safety knobs
        dedupe_ttl_seconds: int = 120,
        max_pending: int = 250,
        # action budget
        budget_window_seconds: int = 300,
        budget_max_actions_per_target: int = 5,
        # corroboration
        require_two_signals_for_high: bool = True,
        corroboration_ttl_seconds: int = 600,
    ) -> None:
        self._mode_resolver = mode_resolver
        self._lock = threading.RLock()

        self._pending_actions: Dict[str, threading.Timer] = {}
        self._gated_actions: Dict[str, ActionRequest] = {}

        # replay defense
        self._recent_actions: Dict[str, float] = {}  # action_id -> first_seen_time

        # rate limiting
        self._budget: Dict[str, BudgetState] = {}  # target -> state

        # two-signal confirmation
        self._corroboration: Dict[str, CorroborationState] = {}  # key -> state

        self._dedupe_ttl_seconds = int(dedupe_ttl_seconds)
        self._max_pending = int(max_pending)

        self._budget_window_seconds = int(budget_window_seconds)
        self._budget_max_actions_per_target = int(budget_max_actions_per_target)

        self._require_two_signals_for_high = bool(require_two_signals_for_high)
        self._corroboration_ttl_seconds = int(corroboration_ttl_seconds)

    # ------------------------ internal hygiene ------------------------

    def _now(self) -> float:
        return time.time()

    def _cleanup(self) -> None:
        """Opportunistic cleanup to keep memory bounded."""
        now = self._now()

        # recent actions
        for k, ts in list(self._recent_actions.items()):
            if now - ts > self._dedupe_ttl_seconds:
                self._recent_actions.pop(k, None)

        # corroboration
        for k, st in list(self._corroboration.items()):
            if now - st.last_seen > self._corroboration_ttl_seconds:
                self._corroboration.pop(k, None)

        # budgets: keep them around, they’re tiny; optionally reset old windows
        for target, st in list(self._budget.items()):
            if now - st.window_start > self._budget_window_seconds * 4:
                self._budget.pop(target, None)

    def _is_duplicate(self, action_id: str) -> bool:
        now = self._now()
        ts = self._recent_actions.get(action_id)
        if ts is None:
            self._recent_actions[action_id] = now
            return False
        return (now - ts) <= self._dedupe_ttl_seconds

    def _consume_budget(self, target: str) -> bool:
        now = self._now()
        st = self._budget.get(target)
        if st is None:
            self._budget[target] = BudgetState(window_start=now, used=1)
            return True

        if now - st.window_start > self._budget_window_seconds:
            st.window_start = now
            st.used = 1
            return True

        if st.used >= self._budget_max_actions_per_target:
            return False

        st.used += 1
        return True

    def _corroborate(self, *, target: str, reason: str) -> int:
        """
        Returns corroboration count within TTL for (target, reason).
        """
        now = self._now()
        key = f"{target}|{reason}"
        st = self._corroboration.get(key)
        if st is None:
            self._corroboration[key] = CorroborationState(first_seen=now, last_seen=now, count=1)
            return 1
        st.last_seen = now
        st.count += 1
        return st.count

    # ------------------------ public API ------------------------

    def schedule_action(self, req: ActionRequest) -> None:
        mode = self._mode_resolver()

        with self._lock:
            self._cleanup()

            # bounded pending protection
            if len(self._pending_actions) + len(self._gated_actions) >= self._max_pending:
                logging.error(f"[OVERSIGHT] Back-pressure: too many pending/gated actions. Dropping {req.action_id}")
                return

            # idempotency
            if self._is_duplicate(req.action_id):
                logging.info(f"[OVERSIGHT] Duplicate suppressed: {req.action_id}")
                return

            # budget
            if not self._consume_budget(req.target):
                logging.warning(
                    f"[OVERSIGHT] Budget exceeded for target={req.target}. Suppressing {req.action_id}."
                )
                return

            # two-signal for HIGH (prevents one-signal nukes)
            if req.severity.upper() == "HIGH" and self._require_two_signals_for_high:
                count = self._corroborate(target=req.target, reason=req.reason)
                logging.info(f"[OVERSIGHT] Corroboration {req.target} reason='{req.reason}' -> {count}")
                if count < 2:
                    # log-only advisory until second signal arrives
                    logging.info(f"[OVERSIGHT] Waiting for second signal before acting on HIGH: {req.action_id}")
                    if mode is OpMode.SHADOW:
                        req.shadow_payload()
                    else:
                        # In HUMAN_GATED/ACTIVE we still don’t stage/arm yet.
                        pass
                    return

            logging.info(f"[OVERSIGHT] Mode={mode.value} | {req.description}")

            # Mode behaviors
            if mode is OpMode.SHADOW:
                req.shadow_payload()
                logging.info("[OVERSIGHT] Advisory logged. No execution.")
                return

            if mode is OpMode.HUMAN_GATED:
                self._gated_actions[req.action_id] = req
                logging.warning(f"[OVERSIGHT] ACTION STAGED: {req.action_id}. Awaiting approval.")
                return

            # ACTIVE: delayed execution with veto window
            logging.warning(
                f"[OVERSIGHT] ACTION PENDING: {req.action_id}. "
                f"Executes in {req.delay_seconds}s unless vetoed."
            )
            timer = threading.Timer(
                req.delay_seconds,
                self._execute_wrapper,
                args=(req.action_id, req.description, req.real_payload),
            )
            timer.daemon = True
            self._pending_actions[req.action_id] = timer
            timer.start()

    def _execute_wrapper(self, action_id: str, description: str, payload: Callable[[], None]) -> None:
        with self._lock:
            timer = self._pending_actions.pop(action_id, None)
            if not timer:
                return

        logging.warning(f"[OVERSIGHT] AUTO-EXECUTING: {description}")
        try:
            payload()
        except Exception as exc:
            logging.error(f"[OVERSIGHT] Execution failed for {action_id}: {exc}")

    def veto_action(self, action_id: str, reason: str) -> bool:
        reason = (reason or "").strip()[:300]  # keep logs sane

        with self._lock:
            timer = self._pending_actions.pop(action_id, None)
            if timer:
                timer.cancel()
                logging.warning(f"[OVERSIGHT] VETOED {action_id}. Reason: {reason}")
                return True

            if action_id in self._gated_actions:
                self._gated_actions.pop(action_id, None)
                logging.warning(f"[OVERSIGHT] GATED ACTION DROPPED {action_id}. Reason: {reason}")
                return True

        logging.warning(f"[OVERSIGHT] VETO FAILED: {action_id} not found.")
        return False

    def approve_gated_action(self, action_id: str) -> bool:
        with self._lock:
            req = self._gated_actions.pop(action_id, None)

        if not req:
            logging.warning(f"[OVERSIGHT] APPROVAL FAILED: {action_id} not staged.")
            return False

        logging.warning(f"[OVERSIGHT] APPROVED: {action_id}. Executing now.")
        try:
            req.real_payload()
            return True
        except Exception as exc:
            logging.error(f"[OVERSIGHT] Approved execution failed for {action_id}: {exc}")
            return False


# ---------------------------------------------------------------------------
# Security Nexus (Top-Level Controller)
# ---------------------------------------------------------------------------

class SecurityNexus:
    def __init__(self, initial_mode: OpMode = OpMode.SHADOW) -> None:
        self._mode = initial_mode
        self.oversight = OversightEngine(self.get_mode)

        logging.info(f"[{SYSTEM_ID}] Nexus Online. Operational Mode={self._mode.value}")

    def set_mode(self, mode: OpMode) -> None:
        self._mode = mode
        logging.warning(f"[{SYSTEM_ID}] Mode switched to {self._mode.value}")

    def get_mode(self) -> OpMode:
        return self._mode

    def handle_threat(self, *, ip_address: str, threat_type: str, severity: str = "MEDIUM") -> str:
        """
        Threat handler that *doesn't* work against you:
        - includes evidence
        - dedupes action IDs with a time component to avoid permanent collisions
        - uses budgets + corroboration inside the oversight layer
        """
        ip_address = (ip_address or "").strip()
        threat_type = (threat_type or "UNKNOWN").strip()

        # action_id includes a coarse time bucket so it doesn't collide forever,
        # while still deduping within the dedupe TTL window.
        bucket = int(time.time() // 30)  # 30-second buckets
        action_id = f"BLOCK-{ip_address}-T{bucket}"

        evidence = {
            "system": SYSTEM_ID,
            "threat_type": threat_type,
            "observed_at": int(time.time()),
        }
        reason = f"{threat_type} detected"

        req = ActionRequest(
            action_id=action_id,
            target=ip_address,
            description=f"Block IP {ip_address}",
            delay_seconds=5,
            severity=severity,
            reason=reason,
            evidence=evidence,
            real_payload=lambda: IntegrationHub.execute_firewall_block(ip_address, reason=reason, evidence=evidence),
            shadow_payload=lambda: IntegrationHub.log_shadow_action(ip_address, reason=reason, evidence=evidence),
        )
        logging.info(f"[THREAT] {threat_type} detected from {ip_address} severity={severity}")
        self.oversight.schedule_action(req)
        return action_id