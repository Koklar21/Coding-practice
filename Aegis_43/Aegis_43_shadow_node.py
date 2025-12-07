import datetime
import logging
import time
import json
import threading
import sqlite3
from enum import Enum
from typing import Callable, Dict

# --- CONFIGURATION ---
SYSTEM_ID = "AEGIS-42-NEXUS-01"
DB_FILENAME = "aegis_secure.db"

# --- OPERATIONAL MODES ---
class OpMode(Enum):
    SHADOW = "SHADOW_ADVISORY"    # Look, don't touch (Zero Risk)
    GATED  = "HUMAN_GATED"        # Wait for "GO" (Low Risk)
    ACTIVE = "ACTIVE_DEFENSE"     # Auto-fire with Veto (High Speed)

# CURRENT CONFIGURATION (Default to SHADOW for deployment)
CURRENT_MODE = OpMode.SHADOW

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s'
)

# ============================================================
#               INTEGRATION HUB (Simulated)
# ============================================================
class IntegrationHub:
    @staticmethod
    def execute_firewall_block(ip_address: str):
        """The actual 'Destructive' call."""
        logging.info(f"🔥 [FIREWALL] HARD BLOCK applied to {ip_address}.")
        return True

    @staticmethod
    def log_shadow_action(ip_address: str):
        """The safe 'Simulation' call."""
        logging.info(f"👻 [SHADOW] Simulation: WOULD have blocked {ip_address}. No action taken.")
        return True

# ============================================================
#               OVERSIGHT ENGINE (Multi-Mode)
# ============================================================
class OversightEngine:
    def __init__(self):
        self.pending_actions: Dict[str, threading.Timer] = {}
        self.lock = threading.RLock()

    def schedule_action(self, action_id: str, description: str, delay: int, real_payload: Callable, shadow_payload: Callable):
        with self.lock:
            if action_id in self.pending_actions:
                return

            logging.info(f"[OVERSIGHT] Processing threat in mode: {CURRENT_MODE.value}")

            if CURRENT_MODE == OpMode.SHADOW:
                # In Shadow Mode, we don't wait. We just log the recommendation and exit.
                shadow_payload()
                logging.info(f"[OVERSIGHT] ℹ️ Recommendation logged. Upgrade to ACTIVE mode to automate.")
                return

            if CURRENT_MODE == OpMode.GATED:
                logging.info(f"[OVERSIGHT] 🛑 Action '{description}' STAGED. Waiting for manual approval...")
                # In real app, this would sit in a DB waiting for API call. 
                # For script demo, we just hold it.
                return

            if CURRENT_MODE == OpMode.ACTIVE:
                logging.info(f"[OVERSIGHT] ⏳ PENDING: '{description}'. Executing in {delay}s unless VETOED.")
                t = threading.Timer(delay, self._execute_wrapper, args=[action_id, description, real_payload])
                self.pending_actions[action_id] = t
                t.start()

    def _execute_wrapper(self, action_id: str, description: str, payload: Callable):
        with self.lock:
            if action_id in self.pending_actions:
                logging.info(f"[OVERSIGHT] ⚡ TIMEOUT -> AUTO-EXECUTING: {description}")
                payload()
                del self.pending_actions[action_id]

    def veto_action(self, action_id: str, user_reason: str):
        with self.lock:
            if action_id in self.pending_actions:
                self.pending_actions[action_id].cancel()
                del self.pending_actions[action_id]
                logging.warning(f"[OVERSIGHT] 🛡️ VETOED: {action_id} by Operator. Reason: {user_reason}")

# ============================================================
#               SECURITY NODE
# ============================================================
class SecurityNode:
    def __init__(self):
        self.oversight = OversightEngine()
        logging.info(f"[{SYSTEM_ID}] System Online. Operational Mode: {CURRENT_MODE.value}")

    def trigger_threat(self, ip: str, threat_type: str):
        logging.info(f"[THREAT_INT] Detected {threat_type} from {ip}")
        
        action_id = f"BLOCK-{ip}"
        
        self.oversight.schedule_action(
            action_id=action_id,
            description=f"Block IP {ip}",
            delay=5, # 5s delay for demo
            real_payload=lambda: IntegrationHub.execute_firewall_block(ip),
            shadow_payload=lambda: IntegrationHub.log_shadow_action(ip)
        )

# ============================================================
#               SIMULATION
# ============================================================
if __name__ == "__main__":
    nexus = SecurityNode()
    
    print("\n--- TEST 1: SHADOW MODE (Default) ---")
    # This should ONLY print the "Ghost" message, no active block.
    nexus.trigger_threat("203.0.113.88", "SQL Injection")
    time.sleep(1) 
    
    print("\n--- SWITCHING CONFIGURATION TO 'ACTIVE' ---")
    # Simulation of Analyst flipping the switch after a month of trust
    CURRENT_MODE = OpMode.ACTIVE
    print(f"Operational Mode updated to: {CURRENT_MODE.value}")
    
    print("\n--- TEST 2: ACTIVE MODE (With Veto Opportunity) ---")
    # This should start the timer
    nexus.trigger_threat("198.51.100.22", "RDP Brute Force")
    
    print(">> Waiting for auto-execution...")
    time.sleep(6) # Wait for timer to expire
