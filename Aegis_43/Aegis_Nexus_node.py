from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .oversight import ActionRequest, IntegrationHub, OpMode, OversightEngine
from .storage_sqlite import AegisSqlite, DbConfig


SYSTEM_ID = os.getenv("AEGIS_SYSTEM_ID", "AEGIS-43-NEXUS-01")


@dataclass(frozen=True)
class NexusConfig:
    db_path: Path
    initial_mode: OpMode = OpMode.SHADOW


class SecurityNexus:
    """
    AEGIS-43 top-level:
      - accepts threats (from your AI detector OR dumb rules)
      - writes incidents to DB
      - hands off to OversightEngine for safe execution
    """

    def __init__(self, cfg: NexusConfig) -> None:
        self.cfg = cfg
        self.mode = cfg.initial_mode

        self.db = AegisSqlite(DbConfig(db_path=cfg.db_path))
        self.db.ensure_schema()

        self.hub = IntegrationHub(self.db)
        self.oversight = OversightEngine(db=self.db, hub=self.hub, mode_resolver=self.get_mode)

        self.db.log("INFO", "NEXUS", f"{SYSTEM_ID} online.", {"mode": self.mode.value, "db": str(cfg.db_path)})

    def set_mode(self, mode: OpMode) -> None:
        self.mode = mode
        self.db.log("WARN", "NEXUS", "Mode switched.", {"mode": self.mode.value})

    def get_mode(self) -> OpMode:
        return self.mode

    def _sanitize_tt(self, threat_type: str) -> str:
        tt = (threat_type or "UNKNOWN").upper()
        tt = "".join(c for c in tt if c.isalnum() or c in ("_", "-"))[:32]
        return tt or "UNKNOWN"

    def intake_threat(
        self,
        *,
        ip: str,
        threat_type: str,
        severity: str = "MEDIUM",
        evidence: Optional[Dict[str, Any]] = None,
        delay_seconds: int = 15,
    ) -> Dict[str, str]:
        ip = (ip or "").strip()
        tt = self._sanitize_tt(threat_type)
        sev = (severity or "MEDIUM").upper()
        if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            sev = "MEDIUM"

        # Action/incident IDs: stable + time bucket to avoid endless collision, but include threat type
        bucket = int(time.time() // 30)
        incident_id = f"INC-{ip}-{tt}-T{bucket}"
        action_id = f"ACT-{ip}-{tt}-T{bucket}"

        reason = f"{tt} detected"
        ev = {
            "system": SYSTEM_ID,
            "threat_type": tt,
            "severity": sev,
            "observed_at": int(time.time()),
            **(evidence or {}),
        }

        # DB truth for UI
        mode = self.mode.value
        status = "SHADOWED" if self.mode == OpMode.SHADOW else ("STAGED" if self.mode == OpMode.HUMAN_GATED else "PENDING")
        self.db.upsert_incident(
            incident_id=incident_id,
            target_ip=ip,
            threat_type=tt,
            severity=sev,
            mode=mode,
            status=status,
            reason=reason,
            evidence=ev,
        )

        self.db.log("INFO", "THREAT", f"Threat intake: {tt} from {ip}", {"incident_id": incident_id, "action_id": action_id})

        req = ActionRequest(
            action_id=action_id,
            incident_id=incident_id,
            target_ip=ip,
            threat_type=tt,
            severity=sev,
            reason=reason,
            evidence=ev,
            delay_seconds=int(delay_seconds),
        )
        self.oversight.schedule(req)

        return {"incident_id": incident_id, "action_id": action_id}