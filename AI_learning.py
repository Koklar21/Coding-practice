import logging
import statistics
import hashlib
import json
import hmac
import threading
import math
import copy
from decimal import Decimal, InvalidOperation, getcontext
from datetime import datetime, timedelta, timezone, date
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from types import MappingProxyType
from collections import deque

"""
SYSTEM: GHOST SYSTEM / INTERNAL AFFAIRS OVERLAY
MODULE: AI Governance & Behavioral Intelligence Engine
VERSION: 2.2 (Financial Hardened / Memory Safe)
STATUS: PRODUCTION

CHANGELOG v2.2:
- Replaced float with Decimal for IEEE 754 financial compliance.
- Added Garbage Collection to VelocityGuard to prevent memory leaks.
- Added Custom JSON Encoder for resilient logging.
"""

# Set Global Precision for Finance
getcontext().prec = 4  # Track up to 4 decimal places internally

# --- CONFIGURATION ---
CONFIG = MappingProxyType({
    "FINANCIAL_HARD_LIMIT": Decimal("50.00"), # Strict Decimal
    "VELOCITY_LIMIT": 3,
    "VELOCITY_WINDOW_SECONDS": 60,
    "RISK_THRESHOLD": Decimal("0.85"),
    "RETENTION_POLICY_DAYS": 2555,
    "POLICY_VERSION": "2.2",
    "FLAC_VERSION": "1.1",
    "AI_VERSION": "1.1",
    "DEVICE_HASH_SECRET": b"rotation-managed-secret",
    "RISK_WEIGHTS": {
        "baseline": Decimal("0.3"),
        "slow_boil": Decimal("0.5"),
        "outlier": Decimal("0.4"),
        "trust_penalty": Decimal("0.2")
    },
    "SLOW_BOIL_WINDOW": 5,
    "OUTLIER_Z": Decimal("3.0"),
    "MAX_HISTORY_LENGTH": 50,
    "MAX_AUDIT_ENTRIES": 10000,
    "GC_INTERVAL_SECONDS": 3600 # Clean up stale users every hour
})

class ReasonCodes:
    FINANCIAL_LIMIT = "FLAC_FAIL_FINANCIAL_LIMIT_EXCEEDED"
    SANCTIONED_LOCATION = "FLAC_FAIL_LEGAL_SANCTIONED_LOCATION"
    DEVICE_UNTRUSTED = "FLAC_FAIL_COMPLIANCE_DEVICE_UNTRUSTED"
    MISSING_METADATA = "FLAC_FAIL_AUDIT_MISSING_METADATA"
    VELOCITY_EXCEEDED = "FLAC_FAIL_VELOCITY_LIMIT"
    INVALID_INPUT = "FLAC_FAIL_INVALID_INPUT"
    INVALID_AMOUNT = "FLAC_FAIL_INVALID_AMOUNT"
    NEGATIVE_AMOUNT = "FLAC_FAIL_NEGATIVE_AMOUNT"
    INVALID_TIMESTAMP = "FLAC_FAIL_INVALID_TIMESTAMP"
    FUTURE_TIMESTAMP = "FLAC_FAIL_FUTURE_TIMESTAMP"
    SERIALIZATION_ERROR = "SYSTEM_SERIALIZATION_ERROR"
    AI_RISK = "AI_RISK_THRESHOLD_EXCEEDED"
    CLEARED = "CLEARED_ALL_CHECKS"
    SYSTEM_ERROR = "SYSTEM_EXCEPTION"

# --- UTILITIES ---
class AuditEncoder(json.JSONEncoder):
    """Ensures logs rarely fail due to data types."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

class AppendOnlyAuditBuffer:
    def __init__(self, max_size: int = CONFIG["MAX_AUDIT_ENTRIES"]):
        self._entries: List[str] = []
        self._lock = threading.Lock()
        self._max_size = max_size

    def append(self, entry_str: str) -> bool:
        with self._lock:
            try:
                if len(self._entries) >= self._max_size:
                    self._entries.pop(0) # Ring buffer behavior
                self._entries.append(entry_str)
                return True
            except Exception:
                return False

_audit_buffer = AppendOnlyAuditBuffer()
_logger = logging.getLogger("GhostSystem_Audit")
_logger.setLevel(logging.INFO)
_logger.addHandler(logging.StreamHandler())

# --- DATA CLASSES ---
@dataclass
class TransactionContext:
    user_id: str
    amount: Decimal # CHANGED: Strict Decimal
    timestamp: datetime
    location: str
    device_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Decision:
    status: str
    risk_score: Decimal
    reason: str

# --- INPUT VALIDATION ---
def validate_context(ctx: TransactionContext) -> Tuple[bool, str]:
    now = datetime.now(timezone.utc)
    
    # Amount Safety
    if not isinstance(ctx.amount, Decimal):
        try:
            # Attempt safe conversion if they passed a string/float/int
            ctx.amount = Decimal(str(ctx.amount))
        except (InvalidOperation, ValueError, TypeError):
             return False, ReasonCodes.INVALID_AMOUNT
             
    if ctx.amount.is_nan() or ctx.amount.is_infinite():
        return False, ReasonCodes.INVALID_AMOUNT
    if ctx.amount < 0:
        return False, ReasonCodes.NEGATIVE_AMOUNT
        
    # Timestamp Safety
    if not isinstance(ctx.timestamp, datetime) or ctx.timestamp.tzinfo is None:
        return False, ReasonCodes.INVALID_TIMESTAMP
    if ctx.timestamp > now + timedelta(minutes=5):
        return False, ReasonCodes.FUTURE_TIMESTAMP
    if ctx.timestamp.year < 2000:
        return False, ReasonCodes.INVALID_TIMESTAMP
        
    # Strings Safety
    for f in ["user_id", "device_id", "location"]:
        val = getattr(ctx, f)
        if not isinstance(val, str) or not val.strip():
            return False, f"FLAC_FAIL_INVALID_{f.upper()}"
            
    return True, ReasonCodes.CLEARED

# --- VELOCITY GUARD (With Garbage Collection) ---
class VelocityGuard:
    def __init__(self):
        self.user_events: Dict[str, deque] = {}
        self.lock = threading.Lock()
        self.last_gc = datetime.now()

    def _garbage_collect(self, now: datetime):
        """Removes stale users to prevent memory leaks."""
        if (now - self.last_gc).total_seconds() > CONFIG["GC_INTERVAL_SECONDS"]:
            stale_keys = []
            cutoff = now - timedelta(seconds=CONFIG["VELOCITY_WINDOW_SECONDS"])
            for uid, events in self.user_events.items():
                if not events or events[-1] < cutoff:
                    stale_keys.append(uid)
            
            for uid in stale_keys:
                del self.user_events[uid]
            self.last_gc = now

    def allow(self, user_id: str, now: datetime) -> bool:
        with self.lock:
            try:
                self._garbage_collect(now) # Run maintenance
                
                dq = self.user_events.setdefault(user_id, deque())
                cutoff = now - timedelta(seconds=CONFIG["VELOCITY_WINDOW_SECONDS"])
                
                # Remove old events
                while dq and dq[0] < cutoff:
                    dq.popleft()
                    
                if len(dq) >= CONFIG["VELOCITY_LIMIT"]:
                    return False
                    
                dq.append(now)
                return True
            except Exception:
                return False  # Fail-closed

# --- AUDIT LOGGING ---
class SecureAuditLog:
    _prev_hash: Optional[str] = None
    _lock = threading.Lock()

    @staticmethod
    def _hmac_device(device_id: str) -> str:
        try:
            return hmac.new(
                CONFIG["DEVICE_HASH_SECRET"],
                device_id.encode(),
                hashlib.sha256
            ).hexdigest()
        except Exception:
            return "HASH_ERROR"

    @staticmethod
    def log_decision(
        context: TransactionContext,
        decision: str,
        reason_code: str,
        risk_score: Decimal,
        risk_components: Dict[str, Decimal],
        model_snapshot: Dict[str, Any]
    ) -> bool:
        with SecureAuditLog._lock:
            try:
                region_code = context.metadata.get("region_code", "UNKNOWN")
                entry = {
                    "event_time": context.timestamp.isoformat(),
                    "decision_time": datetime.now(timezone.utc).isoformat(),
                    "user_id": context.user_id,
                    "decision": decision,
                    "reason": reason_code,
                    "risk_score": risk_score, # Decimal (handled by encoder)
                    "risk_components": risk_components, # Decimals
                    "amount": context.amount, # Decimal
                    "device_hash": SecureAuditLog._hmac_device(context.device_id),
                    "region_code": region_code,
                    "policy_ver": CONFIG["POLICY_VERSION"],
                    "prev_hash": SecureAuditLog._prev_hash or "GENESIS",
                }
                
                # Use Custom Encoder for safety
                entry_str = json.dumps(entry, cls=AuditEncoder, sort_keys=True, separators=(",", ":"))
                curr_hash = hashlib.sha256(entry_str.encode()).hexdigest()
                
                # Hash the payload, not the entry with the hash (prevents circular logic)
                final_packet = {
                    "payload": json.loads(entry_str),
                    "hash": curr_hash
                }
                final_str = json.dumps(final_packet, cls=AuditEncoder)

                if not _audit_buffer.append(final_str):
                    return False
                    
                SecureAuditLog._prev_hash = curr_hash
                _logger.info(final_str)
                return True
            except Exception as e:
                _logger.error(f"Audit log failed: {e}")
                return False

# --- GOVERNANCE ---
class GovernanceFramework:
    def __init__(self, sanctioned_locations: List[str]):
        self.sanctioned_locations: Set[str] = set(sanctioned_locations or [])

    def run_flac_loops(self, context: TransactionContext) -> Tuple[bool, str]:
        try:
            if context.amount > CONFIG["FINANCIAL_HARD_LIMIT"]:
                return False, ReasonCodes.FINANCIAL_LIMIT
            if context.location in self.sanctioned_locations:
                return False, ReasonCodes.SANCTIONED_LOCATION
            if context.metadata.get("device_integrity") == "compromised":
                return False, ReasonCodes.DEVICE_UNTRUSTED
            if not context.metadata:
                return False, ReasonCodes.MISSING_METADATA
            return True, ReasonCodes.CLEARED
        except Exception:
            return False, ReasonCodes.SYSTEM_ERROR

# --- ADAPTIVE INTELLIGENCE (Decimal Safe) ---
class AdaptiveIntelligence:
    def __init__(self):
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def get_baseline(self, user_id: str) -> Dict[str, Any]:
        with self.lock:
            # Return deepcopy to prevent race conditions on read
            return copy.deepcopy(self.profiles.get(user_id, {
                "history": [], 
                "trust_score": Decimal("0.5")
            }))

    @staticmethod
    def _linear_regression_slope(vals: List[Decimal]) -> Decimal:
        try:
            n = len(vals)
            if n < 2: return Decimal(0)
            
            # Convert to float for stat calc (speed), then back to Decimal? 
            # Better to stay in Decimal for precision, but slower.
            # Using simple Decimal math here:
            x_vals = [Decimal(i) for i in range(n)]
            y_vals = vals
            
            mean_x = sum(x_vals) / n
            mean_y = sum(y_vals) / n
            
            numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(x_vals, y_vals))
            denominator = sum((x - mean_x) ** 2 for x in x_vals)
            
            if denominator == 0: return Decimal(0)
            return numerator / denominator
        except Exception:
            return Decimal(0)

    def detect_slow_boil(self, history: List[Decimal], current_amount: Decimal) -> bool:
        try:
            window = CONFIG["SLOW_BOIL_WINDOW"]
            if len(history) < window - 1:
                return False
            # Look at last N + current
            series = history[-(window - 1):] + [current_amount]
            slope = self._linear_regression_slope(series)
            return slope > 0
        except Exception:
            return False

    def evaluate_risk(self, context: TransactionContext) -> Tuple[Decimal, Dict[str, Decimal], Dict[str, Any]]:
        try:
            profile = self.get_baseline(context.user_id)
            history: List[Decimal] = profile["history"]
            components: Dict[str, Decimal] = {}
            weights = CONFIG["RISK_WEIGHTS"]

            # Baseline Risk
            if not history:
                components["baseline"] = weights["baseline"]
                components["slow_boil"] = Decimal(0)
                components["outlier"] = Decimal(0)
            else:
                components["baseline"] = weights["baseline"] if len(history) < 5 else Decimal(0)
                components["slow_boil"] = weights["slow_boil"] if self.detect_slow_boil(history, context.amount) else Decimal(0)
                
                # Outlier (Z-Score)
                if len(history) >= 5:
                    # statistics module works better with floats, converting safely
                    float_hist = [float(h) for h in history]
                    mu = Decimal(str(statistics.mean(float_hist)))
                    sigma = Decimal(str(statistics.pstdev(float_hist))) or Decimal(1)
                    
                    z = (context.amount - mu) / sigma if sigma != 0 else Decimal(0)
                    components["outlier"] = weights["outlier"] if z > CONFIG["OUTLIER_Z"] else Decimal(0)
                else:
                    components["outlier"] = Decimal(0)

            trust_score = profile.get("trust_score", Decimal("0.5"))
            penalty_base = Decimal("0.5") - trust_score
            components["trust_penalty"] = max(Decimal(0), penalty_base) * weights["trust_penalty"]
            
            risk = sum(components.values())
            risk = min(risk, Decimal("1.0"))

            # Snapshot for Explainability
            snapshot = {
                "history_len": len(history),
                "trust_score": trust_score
            }
            return risk, components, snapshot
        except Exception as e:
            # Fail closed on calculation error
            return Decimal("1.0"), {"error": Decimal("1.0")}, {"error_msg": str(e)}

    def learn(self, context: TransactionContext) -> None:
        with self.lock:
            try:
                profile = self.profiles.get(context.user_id, {"history": [], "trust_score": Decimal("0.5")})
                profile["history"].append(context.amount)
                if len(profile["history"]) > CONFIG["MAX_HISTORY_LENGTH"]:
                    profile["history"].pop(0)
                self.profiles[context.user_id] = profile
            except Exception:
                pass

    def reward_trust(self, user_id: str, delta: Decimal = Decimal("0.01")) -> None:
        with self.lock:
            try:
                profile = self.profiles.get(user_id, {"history": [], "trust_score": Decimal("0.5")})
                curr = profile["trust_score"]
                new_trust = max(Decimal(0), min(Decimal(1), curr + delta))
                profile["trust_score"] = new_trust
                self.profiles[user_id] = profile
            except Exception:
                pass

# --- ORCHESTRATOR ---
class SystemOrchestrator:
    def __init__(self, sanctioned_locations: List[str]):
        self.governance = GovernanceFramework(sanctioned_locations)
        self.ai = AdaptiveIntelligence()
        self.auditor = SecureAuditLog()
        self.velocity_guard = VelocityGuard()

    def process_transaction(self, user_id: str, amount_str: str, metadata: Dict[str, Any]) -> Decision:
        """
        Main entry point. Accepting amount as String to ensure Decimal precision from the start.
        """
        # 0. Instantiation
        try:
             safe_amount = Decimal(amount_str)
        except:
             return Decision("ERROR", Decimal("1.0"), ReasonCodes.INVALID_AMOUNT)

        ctx = TransactionContext(
            user_id=user_id,
            amount=safe_amount,
            timestamp=datetime.now(timezone.utc),
            location=metadata.get("location", "UNKNOWN"),
            device_id=metadata.get("device_id", "UNKNOWN"),
            metadata=metadata
        )
        
        try:
            # 1. Validate
            valid, msg = validate_context(ctx)
            if not valid:
                self.auditor.log_decision(ctx, "BLOCKED", msg, Decimal(0), {}, {"validation_error": msg})
                return Decision("BLOCKED", Decimal(0), msg)

            # 2. Velocity
            if not self.velocity_guard.allow(user_id, ctx.timestamp):
                self.auditor.log_decision(ctx, "BLOCKED", ReasonCodes.VELOCITY_EXCEEDED, Decimal(0), {}, {})
                return Decision("BLOCKED", Decimal(0), ReasonCodes.VELOCITY_EXCEEDED)

            # 3. FLAC
            flac_passed, flac_reason = self.governance.run_flac_loops(ctx)
            if not flac_passed:
                self.auditor.log_decision(ctx, "BLOCKED", flac_reason, Decimal(0), {}, {})
                return Decision("BLOCKED", Decimal(0), flac_reason)

            # 4. Risk
            risk_score, components, snapshot = self.ai.evaluate_risk(ctx)
            if risk_score > CONFIG["RISK_THRESHOLD"]:
                self.auditor.log_decision(ctx, "FLAGGED", ReasonCodes.AI_RISK, risk_score, components, snapshot)
                return Decision("FLAGGED", risk_score, ReasonCodes.AI_RISK)

            # 5. Approve
            if not self.auditor.log_decision(ctx, "APPROVED", ReasonCodes.CLEARED, risk_score, components, snapshot):
                return Decision("ERROR", Decimal("1.0"), ReasonCodes.SYSTEM_ERROR)
                
            self.ai.learn(ctx)
            self.ai.reward_trust(user_id)
            return Decision("APPROVED", risk_score, ReasonCodes.CLEARED)

        except Exception as e:
            # Catch-all for Murphy
            self.auditor.log_decision(ctx, "ERROR", ReasonCodes.SYSTEM_ERROR, Decimal("1.0"), {}, {"exception": str(e)})
            return Decision("ERROR", Decimal("1.0"), ReasonCodes.SYSTEM_ERROR)

# --- EXPORT ---
engine = SystemOrchestrator(sanctioned_locations=["BLOCKED_REGION_1"])