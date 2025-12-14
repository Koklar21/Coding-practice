from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# -------------------------
# Option A: DB next to file
# -------------------------
try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path.cwd()

DB_PATH = Path(os.getenv("AEGIS_DB_PATH", str(BASE_DIR / "aegis_secure.db")))

SYSTEM_ID = os.getenv("AEGIS_SYSTEM_ID", "AEGIS-43-NEXUS-01")

# -------------------------
# Auth (JWT placeholder)
# -------------------------
# For now: symmetric HMAC token for prototype. Replace with OIDC/JWKS later.
JWT_SECRET = os.getenv("AEGIS_JWT_SECRET", "dev-only-change-me")
JWT_ISSUER = os.getenv("AEGIS_JWT_ISSUER", "aegis")
JWT_AUDIENCE = os.getenv("AEGIS_JWT_AUDIENCE", "aegis-remote")

security = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    sub: str
    role: str  # viewer/operator/admin


def _b64url_decode(data: str) -> bytes:
    import base64
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def verify_jwt(token: str) -> Principal:
    """
    Minimal JWT HS256 verification for prototype.
    Replace with proper OIDC (RS256 + JWKS) in production.
    """
    import hmac
    import hashlib

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Bad token format")

    header_b64, payload_b64, sig_b64 = parts
    signed = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected = hmac.new(JWT_SECRET.encode("utf-8"), signed, hashlib.sha256).digest()
    actual = _b64url_decode(sig_b64)

    if not hmac.compare_digest(expected, actual):
        raise ValueError("Bad signature")

    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))

    # Minimal claims
    if payload.get("iss") != JWT_ISSUER:
        raise ValueError("Bad issuer")
    aud = payload.get("aud")
    if aud != JWT_AUDIENCE:
        raise ValueError("Bad audience")

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < int(time.time()):
        raise ValueError("Expired token")

    sub = payload.get("sub", "unknown")
    role = payload.get("role", "viewer")
    if role not in ("viewer", "operator", "admin"):
        role = "viewer"

    return Principal(sub=sub, role=role)


def get_principal(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Principal:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        return verify_jwt(creds.credentials)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}")


def require_role(*allowed: str):
    def _dep(p: Principal = Depends(get_principal)) -> Principal:
        if p.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return p
    return _dep


# -------------------------
# DB helpers
# -------------------------
def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def read_tail(limit: int = 200) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, level, module, message, context_json
            FROM event_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "level": r["level"],
            "module": r["module"],
            "message": r["message"],
            "context": json.loads(r["context_json"]) if r["context_json"] else None,
        }
        for r in reversed(rows)
    ]


# -------------------------
# API models
# -------------------------
class VetoRequest(BaseModel):
    reason: str


class LogWrite(BaseModel):
    level: str = "INFO"
    module: str = "UI"
    message: str
    context: Optional[Dict[str, Any]] = None


# -------------------------
# App
# -------------------------
app = FastAPI(title="AEGIS Remote Access Gateway", version="0.1.0")


@app.get("/api/v1/health")
def health(_: Principal = Depends(require_role("viewer", "operator", "admin"))):
    return {"ok": True, "system_id": SYSTEM_ID, "db_path": str(DB_PATH)}


@app.get("/api/v1/logs/tail")
def logs_tail(limit: int = 200, _: Principal = Depends(require_role("viewer", "operator", "admin"))):
    try:
        return {"items": read_tail(limit)}
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")


@app.post("/api/v1/logs")
def write_log(entry: LogWrite, p: Principal = Depends(require_role("operator", "admin"))):
    ts = __import__("datetime").datetime.utcnow().isoformat(timespec="microseconds") + "Z"
    ctx = json.dumps(entry.context, default=str) if entry.context else None

    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO event_logs (timestamp, level, module, message, context_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ts, entry.level, entry.module, entry.message, ctx),
        )

    return {"ok": True}


@app.post("/api/v1/actions/{action_id}/veto")
def veto_action(action_id: str, body: VetoRequest, p: Principal = Depends(require_role("operator", "admin"))):
    # This endpoint logs the veto. Your in-process OversightEngine would also be notified
    # when you run this gateway alongside the Nexus runtime.
    ts = __import__("datetime").datetime.utcnow().isoformat(timespec="microseconds") + "Z"
    ctx = json.dumps({"action_id": action_id, "operator_id": p.sub, "reason": body.reason}, default=str)

    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO event_logs (timestamp, level, module, message, context_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ts, "INFO", "OVERSIGHT", f"[OVERSIGHT] VETOED: {action_id} by {p.sub}. Reason: {body.reason}", ctx),
        )

    return {"ok": True, "action_id": action_id, "operator": p.sub}


# NOTE:
# Pending actions live in-memory in your OversightEngine today.
# For true remote control across restarts, you should persist staged/pending actions in a DB table.
# We'll add that next (pending_actions table + lifecycle states).