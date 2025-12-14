"""
AEGIS-43 Package Initialization

Purpose:
- Single place to bootstrap config, paths, and logging
- Provide factory functions for:
  - Nexus SecurityNode runtime
  - Remote Access Gateway (FastAPI) app
- Avoid side effects on import (no demo runs, no network binds, no sleeps)

Usage:
- From CLI runner: import aegis_43 as aegis; node = aegis.create_nexus()
- From ASGI server: import aegis_43 as aegis; app = aegis.create_gateway_app()
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ----------------------------
# Version / Identity
# ----------------------------
__all__ = [
    "__version__",
    "AegisConfig",
    "resolve_base_dir",
    "configure_logging",
    "create_nexus",
    "create_gateway_app",
]

__version__ = "0.1.0"

SYSTEM_ID_DEFAULT = "AEGIS-43-NEXUS-01"
DB_FILENAME_DEFAULT = "aegis_secure.db"
LOG_FILENAME_DEFAULT = "aegis_system.log"

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
    default_mode: str  # keep as str to avoid tight coupling across files


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
        # Some restricted environments
        return Path.cwd().resolve()


def load_config() -> AegisConfig:
    base_dir = resolve_base_dir()

    system_id = os.getenv("AEGIS_SYSTEM_ID", SYSTEM_ID_DEFAULT)

    db_path = Path(os.getenv("AEGIS_DB_PATH", str(base_dir / DB_FILENAME_DEFAULT))).expanduser().resolve()
    log_path = Path(os.getenv("AEGIS_LOG_PATH", str(base_dir / LOG_FILENAME_DEFAULT))).expanduser().resolve()

    gateway_host = os.getenv("AEGIS_GATEWAY_HOST", "0.0.0.0")
    gateway_port = int(os.getenv("AEGIS_GATEWAY_PORT", "8080"))

    jwt_secret = os.getenv("AEGIS_JWT_SECRET", "dev-only-change-me")
    jwt_issuer = os.getenv("AEGIS_JWT_ISSUER", "aegis")
    jwt_audience = os.getenv("AEGIS_JWT_AUDIENCE", "aegis-remote")

    default_mode = os.getenv("AEGIS_DEFAULT_MODE", "SHADOW")

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

    # Ensure parent dir exists
    try:
        cfg.log_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If filesystem is locked down, fall back to console only.
        pass

    handlers = [logging.StreamHandler()]
    try:
        handlers.insert(0, logging.FileHandler(cfg.log_path, encoding="utf-8"))
    except Exception:
        # Console-only fallback
        pass

    logging.basicConfig(
        level=os.getenv("AEGIS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)-8s | %(module)-18s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )

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
    Returns your Nexus runtime object (SecurityNode / Nexus node).
    This function intentionally avoids importing heavy modules until needed.
    """
    cfg = config or load_config()
    configure_logging(cfg)

    # Lazy import so __init__.py doesn't explode if files move during refactors
    try:
        # Prefer your current Nexus file name
        from .Aegis_Nexus_node import SecurityNode  # type: ignore
    except Exception:
        # Fallback to other common names you used
        from .Aegis_43 import SecurityNode  # type: ignore

    # Construct node with DB path etc if your constructor supports it.
    # If your SecurityNode currently hardcodes DB filename, update it later to accept db_path.
    node = SecurityNode()  # keep simple; your node already binds PersistenceManager internally
    logging.info(f"[BOOT] Nexus created. system_id={cfg.system_id} db={cfg.db_path}")
    return node


def create_gateway_app(config: Optional[AegisConfig] = None):
    """
    Returns the FastAPI app for remote access.
    Expects aegis_remote_gateway.py to define `app` OR a `create_app(config)` function.
    """
    cfg = config or load_config()
    configure_logging(cfg)

    # Provide config to gateway through env for now (simple + works everywhere)
    os.environ.setdefault("AEGIS_DB_PATH", str(cfg.db_path))
    os.environ.setdefault("AEGIS_SYSTEM_ID", cfg.system_id)
    os.environ.setdefault("AEGIS_JWT_SECRET", cfg.jwt_secret)
    os.environ.setdefault("AEGIS_JWT_ISSUER", cfg.jwt_issuer)
    os.environ.setdefault("AEGIS_JWT_AUDIENCE", cfg.jwt_audience)

    try:
        from .aegis_remote_gateway import app  # type: ignore
        logging.info("[BOOT] Remote Gateway app loaded (module-level app).")
        return app
    except Exception:
        # If you later refactor gateway to expose a factory:
        from .aegis_remote_gateway import create_app  # type: ignore
        logging.info("[BOOT] Remote Gateway app created (factory).")
        return create_app(cfg)