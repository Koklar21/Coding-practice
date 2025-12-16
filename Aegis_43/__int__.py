"""
AEGIS-43 Package Initialization

Purpose:
- Single place to bootstrap config, paths, and logging
- Provide factory functions for:
  - Nexus SecurityNode runtime
  - Remote Access Gateway (FastAPI) app
- Avoid side effects on import (no demo runs, no network binds, no sleeps)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = [
    "__version__",
    "AegisConfig",
    "resolve_base_dir",
    "load_config",
    "configure_logging",
    "create_nexus",
    "create_gateway_app",
]

__version__ = "0.1.0"

SYSTEM_ID_DEFAULT = "AEGIS-43-NEXUS-01"
DB_FILENAME_DEFAULT = "aegis_secure.db"
LOG_FILENAME_DEFAULT = "aegis_system.log"

_ALLOWED_MODES = {"SHADOW", "HUMAN_GATED", "ACTIVE"}  # keep stringly-typed but validated


# ----------------------------
# Config
# ----------------------------

@dataclass(frozen=True)
class AegisConfig:
    system_id: str
    base_dir: Path
    db_path: Path
    log_path: Path

    # Remote gateway settings
    gateway_host: str
    gateway_port: int

    # Auth settings (prototype)
    jwt_secret: str
    jwt_issuer: str
    jwt_audience: str

    # Operational defaults
    default_mode: str  # validated string


def resolve_base_dir() -> Path:
    """
    Option A path policy:
    - Default: base_dir is the directory containing this package.
    - Override with AEGIS_BASE_DIR env var.
    """
    env = os.getenv("AEGIS_BASE_DIR")
    if env:
        return Path(env).expanduser().resolve()

    try:
        return Path(__file__).resolve().parent
    except NameError:
        return Path.cwd().resolve()


def _resolve_path(env_key: str, default_path: Path) -> Path:
    raw = os.getenv(env_key)
    if raw:
        return Path(raw).expanduser().resolve()
    return default_path.expanduser().resolve()


def _require_secret(name: str, value: str) -> None:
    """
    Public-safe behavior:
    - In production, do not allow the "dev-only-change-me" default.
    - You can still run locally by setting AEGIS_ENV=dev.
    """
    env = os.getenv("AEGIS_ENV", "dev").lower()
    if env != "dev":
        if not value or value.strip() == "" or value.strip() == "dev-only-change-me":
            raise RuntimeError(f"{name} must be set for non-dev environments.")


def load_config() -> AegisConfig:
    base_dir = resolve_base_dir()

    system_id = os.getenv("AEGIS_SYSTEM_ID", SYSTEM_ID_DEFAULT)

    db_path = _resolve_path("AEGIS_DB_PATH", base_dir / DB_FILENAME_DEFAULT)
    log_path = _resolve_path("AEGIS_LOG_PATH", base_dir / LOG_FILENAME_DEFAULT)

    gateway_host = os.getenv("AEGIS_GATEWAY_HOST", "0.0.0.0")
    gateway_port = int(os.getenv("AEGIS_GATEWAY_PORT", "8080"))

    jwt_secret = os.getenv("AEGIS_JWT_SECRET", "dev-only-change-me")
    jwt_issuer = os.getenv("AEGIS_JWT_ISSUER", "aegis")
    jwt_audience = os.getenv("AEGIS_JWT_AUDIENCE", "aegis-remote")

    default_mode = os.getenv("AEGIS_DEFAULT_MODE", "SHADOW").upper()
    if default_mode not in _ALLOWED_MODES:
        raise ValueError(f"AEGIS_DEFAULT_MODE invalid: {default_mode}. Allowed: {sorted(_ALLOWED_MODES)}")

    _require_secret("AEGIS_JWT_SECRET", jwt_secret)

    return AegisConfig(
        system_id=system_id,
        base_dir=base_dir,
        db_path=db_path,
        log_path=log_path,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        jwt_secret=jwt_secret,
        jwt_issuer=jwt_issuer,
        jwt_audience=jwt_audience,
        default_mode=default_mode,
    )


# ----------------------------
# Logging Bootstrap
# ----------------------------

_LOGGING_CONFIGURED = False

def configure_logging(config: Optional[AegisConfig] = None) -> None:
    """
    Idempotent logging setup. Safe to call multiple times.
    Writes to both file + console when possible.
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    cfg = config or load_config()

    handlers = [logging.StreamHandler()]

    # Try file logging; if it fails, console-only is fine.
    try:
        cfg.log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.insert(0, logging.FileHandler(cfg.log_path, encoding="utf-8"))
    except Exception:
        pass

    logging.basicConfig(
        level=os.getenv("AEGIS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)-8s | %(module)-18s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )

    # Keep server logs readable if you use uvicorn
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    _LOGGING_CONFIGURED = True
    logging.info(f"[BOOT] Logging configured. system_id={cfg.system_id} log={cfg.log_path}")


# ----------------------------
# Factories
# ----------------------------

def create_nexus(config: Optional[AegisConfig] = None):
    """
    Returns your Nexus runtime object.
    Avoids importing heavy modules until needed.
    """
    cfg = config or load_config()
    configure_logging(cfg)

    # Lazy import so package init doesn't explode during refactors
    SecurityNode = None
    import_errors = []

    for mod_name in (".Aegis_Nexus_node", ".Aegis_43", ".aegis_nexus_node", ".aegis_43"):
        try:
            module = __import__(__name__ + mod_name, fromlist=["SecurityNode"])
            SecurityNode = getattr(module, "SecurityNode")
            break
        except Exception as exc:
            import_errors.append(f"{mod_name}: {exc}")

    if SecurityNode is None:
        raise ImportError("Could not import SecurityNode. Tried:\n- " + "\n- ".join(import_errors))

    # Prefer passing paths explicitly if your constructor supports it.
    try:
        node = SecurityNode(db_path=cfg.db_path, system_id=cfg.system_id, default_mode=cfg.default_mode)
    except TypeError:
        # Backward-compatible: your current node may not accept these args yet.
        node = SecurityNode()

    logging.info(f"[BOOT] Nexus created. system_id={cfg.system_id} db={cfg.db_path} mode={cfg.default_mode}")
    return node


def create_gateway_app(config: Optional[AegisConfig] = None):
    """
    Returns the FastAPI app for remote access.
    Supports either:
    - module-level `app`
    - factory `create_app(config)`
    """
    cfg = config or load_config()
    configure_logging(cfg)

    # Minimal env bridging for downstream modules that still read env vars.
    # Prefer passing cfg into create_app when available.
    os.environ.setdefault("AEGIS_DB_PATH", str(cfg.db_path))
    os.environ.setdefault("AEGIS_SYSTEM_ID", cfg.system_id)
    os.environ.setdefault("AEGIS_JWT_ISSUER", cfg.jwt_issuer)
    os.environ.setdefault("AEGIS_JWT_AUDIENCE", cfg.jwt_audience)

    # Only set JWT secret in env if it isn't already there (avoid stomping on secrets manager)
    if "AEGIS_JWT_SECRET" not in os.environ:
        os.environ["AEGIS_JWT_SECRET"] = cfg.jwt_secret

    try:
        from .aegis_remote_gateway import create_app  # type: ignore
        logging.info("[BOOT] Remote Gateway app created (factory).")
        return create_app(cfg)
    except Exception:
        from .aegis_remote_gateway import app  # type: ignore
        logging.info("[BOOT] Remote Gateway app loaded (module-level app).")
        return app