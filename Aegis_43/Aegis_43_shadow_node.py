import logging
import threading
import time
from enum import Enum
from typing import Callable, Dict

SYSTEM_ID = "AEGIS-42-NEXUS-01"


class OpMode(Enum):
    SHADOW = "SHADOW_ADVISORY"
    GATED = "HUMAN_GATED"
    ACTIVE = "ACTIVE_DEFENSE"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s",
)


class IntegrationHub:
    @staticmethod
    def execute_firewall_block(ip_address: str) -> bool:
        logging.info(f"🔥 [FIREWALL] HARD BLOCK applied to {ip_address}.")
        return True

    @staticmethod
    def log_shadow_action(ip_address: str) -> bool:
        logging.info(
            f"👻 [SHADOW] Simulation: WOULD have blocked {ip_address}. No action taken."
        )
        return True


class OversightEngine:
    def __init__(self, mode_resolver: Callable[[], OpMode]) -> None:
        self.pending_actions: Dict[str, threading.Timer] = {}
        self.lock = threading.RLock()
        self._mode_resolver = mode_resolver
        self._gated_actions: Dict[str, Callable[[], None]] = {}

    def schedule_action(
        self,
        action_id: str,
        description: str,
        delay: int,
        real_payload: Callable[[], None],
        shadow_payload: Callable[[], None],
    ) -> None:
        mode = self._mode_resolver()
        with self.lock:
            if action_id in self.pending_actions or action_id in self._gated_actions:
                return

            logging.info(f"[OVERSIGHT] Processing threat in mode: {mode.value}")

            if mode is OpMode.SHADOW:
                shadow_payload()
                logging.info(
                    "[OVERSIGHT] ℹ️ Recommendation logged. Upgrade to ACTIVE mode to automate."
                )
                return

            if mode is OpMode.GATED:
                logging.info(
                    f"[OVERSIGHT] 🛑 Action '{description}' STAGED. Waiting for manual approval..."
                )
                self._gated_actions[action_id] = real_payload
                return

            if mode is OpMode.ACTIVE:
                logging.info(
                    f"[OVERSIGHT] ⏳ PENDING: '{description}'. Executing in {delay}s unless VETOED."
                )
                timer = threading.Timer(
                    delay, self._execute_wrapper, args=[action_id, description, real_payload]
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
            timer = self.pending_actions.get(action_id)
            if not timer:
                return
            self.pending_actions.pop(action_id, None)

        logging.info(f"[OVERSIGHT] ⚡ TIMEOUT -> AUTO-EXECUTING: {description}")
        try:
            payload()
        except Exception as exc:
            logging.error(f"[OVERSIGHT] Execution failed for {action_id}: {exc}")

    def veto_action(self, action_id: str, user_reason: str) -> None:
        with self.lock:
            timer = self.pending_actions.get(action_id)
            if timer:
                timer.cancel()
                self.pending_actions.pop(action_id, None)
                logging.warning(
                    f"[OVERSIGHT] 🛡️ VETOED: {action_id} by Operator. Reason: {user_reason}"
                )
                return

            if action_id in self._gated_actions:
                self._gated_actions.pop(action_id, None)
                logging.warning(
                    f"[OVERSIGHT] 🛡️ GATED ACTION DROPPED: {action_id} by Operator. Reason: {user_reason}"
                )
                return

            logging.warning(
                f"[OVERSIGHT] VETO requested for {action_id}, but no matching action found."
            )

    def approve_gated_action(self, action_id: str) -> None:
        with self.lock:
            payload = self._gated_actions.get(action_id)
            if not payload:
                logging.warning(
                    f"[OVERSIGHT] APPROVAL requested for {action_id}, but no staged action found."
                )
                return
            self._gated_actions.pop(action_id, None)

        logging.info(f"[OVERSIGHT] ✅ APPROVED: {action_id}. Executing now.")
        try:
            payload()
        except Exception as exc:
            logging.error(f"[OVERSIGHT] GATED execution failed for {action_id}: {exc}")


class SecurityNode:
    def __init__(self, initial_mode: OpMode = OpMode.SHADOW) -> None:
        self._mode = initial_mode
        self.oversight = OversightEngine(self.get_mode)
        logging.info(
            f"[{SYSTEM_ID}] System Online. Operational Mode: {self._mode.value}"
        )

    def set_mode(self, mode: OpMode) -> None:
        self._mode = mode
        logging.info(f"[{SYSTEM_ID}] Operational Mode updated to: {self._mode.value}")

    def get_mode(self) -> OpMode:
        return self._mode

    def trigger_threat(self, ip: str, threat_type: str) -> None:
        logging.info(f"[THREAT_INT] Detected {threat_type} from {ip}")
        action_id = f"BLOCK-{ip}"
        self.oversight.schedule_action(
            action_id=action_id,
            description=f"Block IP {ip}",
            delay=5,
            real_payload=lambda: IntegrationHub.execute_firewall_block(ip),
            shadow_payload=lambda: IntegrationHub.log_shadow_action(ip),
        )


if __name__ == "__main__":
    nexus = SecurityNode(initial_mode=OpMode.SHADOW)

    print("\n--- TEST 1: SHADOW MODE (Default) ---")
    nexus.trigger_threat("203.0.113.88", "SQL Injection")
    time.sleep(1)

    print("\n--- SWITCHING CONFIGURATION TO 'ACTIVE' ---")
    nexus.set_mode(OpMode.ACTIVE)

    print("\n--- TEST 2: ACTIVE MODE (With Veto Opportunity) ---")
    nexus.trigger_threat("198.51.100.22", "RDP Brute Force")
    print(">> Waiting for auto-execution...")
    time.sleep(6)
