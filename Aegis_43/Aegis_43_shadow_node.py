import logging
import threading
from enum import Enum
from typing import Callable, Dict

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
    """All real-world effects terminate here."""

    @staticmethod
    def execute_firewall_block(ip_address: str) -> bool:
        logging.info(f"[FIREWALL] HARD BLOCK applied to {ip_address}.")
        return True

    @staticmethod
    def log_shadow_action(ip_address: str) -> bool:
        logging.info(
            f"[SHADOW] Simulation: WOULD have blocked {ip_address}. No action taken."
        )
        return True


# ---------------------------------------------------------------------------
# Oversight Engine (Veto + Gating)
# ---------------------------------------------------------------------------

class OversightEngine:
    def __init__(self, mode_resolver: Callable[[], OpMode]) -> None:
        self._mode_resolver = mode_resolver
        self._lock = threading.RLock()
        self._pending_actions: Dict[str, threading.Timer] = {}
        self._gated_actions: Dict[str, Callable[[], None]] = {}

    def schedule_action(
        self,
        *,
        action_id: str,
        description: str,
        delay_seconds: int,
        real_payload: Callable[[], None],
        shadow_payload: Callable[[], None],
    ) -> None:
        mode = self._mode_resolver()

        with self._lock:
            if action_id in self._pending_actions or action_id in self._gated_actions:
                logging.warning(f"[OVERSIGHT] Duplicate action ignored: {action_id}")
                return

            logging.info(f"[OVERSIGHT] Mode={mode.value} | {description}")

            if mode is OpMode.SHADOW:
                shadow_payload()
                logging.info("[OVERSIGHT] Advisory logged. No execution.")
                return

            if mode is OpMode.HUMAN_GATED:
                self._gated_actions[action_id] = real_payload
                logging.warning(
                    f"[OVERSIGHT] ACTION STAGED: {action_id}. Awaiting approval."
                )
                return

            if mode is OpMode.ACTIVE:
                logging.warning(
                    f"[OVERSIGHT] ACTION PENDING: {action_id}. "
                    f"Executes in {delay_seconds}s unless vetoed."
                )
                timer = threading.Timer(
                    delay_seconds,
                    self._execute_wrapper,
                    args=(action_id, description, real_payload),
                )
                timer.daemon = True
                self._pending_actions[action_id] = timer
                timer.start()

    def _execute_wrapper(
        self,
        action_id: str,
        description: str,
        payload: Callable[[], None],
    ) -> None:
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
            payload = self._gated_actions.pop(action_id, None)

        if not payload:
            logging.warning(f"[OVERSIGHT] APPROVAL FAILED: {action_id} not staged.")
            return False

        logging.warning(f"[OVERSIGHT] APPROVED: {action_id}. Executing now.")
        try:
            payload()
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

        logging.info(
            f"[{SYSTEM_ID}] Nexus Online. Operational Mode={self._mode.value}"
        )

    def set_mode(self, mode: OpMode) -> None:
        self._mode = mode
        logging.warning(f"[{SYSTEM_ID}] Mode switched to {self._mode.value}")

    def get_mode(self) -> OpMode:
        return self._mode

    def handle_threat(self, *, ip_address: str, threat_type: str) -> str:
        action_id = f"BLOCK-{ip_address}"
        logging.info(f"[THREAT] {threat_type} detected from {ip_address}")

        self.oversight.schedule_action(
            action_id=action_id,
            description=f"Block IP {ip_address}",
            delay_seconds=5,
            real_payload=lambda: IntegrationHub.execute_firewall_block(ip_address),
            shadow_payload=lambda: IntegrationHub.log_shadow_action(ip_address),
        )
        return action_id