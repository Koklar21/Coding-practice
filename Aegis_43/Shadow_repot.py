import argparse
import datetime
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any


try:
    DEFAULT_DB = str(Path(__file__).resolve().parent / "aegis_secure.db")
except NameError:
    DEFAULT_DB = str(Path.cwd() / "aegis_secure.db")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate a shadow-mode style report from AEGIS event logs.")
    p.add_argument("--db", dest="db_path", default=DEFAULT_DB, help=f"Path to SQLite DB (default: {DEFAULT_DB})")
    p.add_argument("--days", type=int, default=7, help="How many days back to include (default: 7).")
    p.add_argument("--limit-samples", type=int, default=10, help="Max sample log lines (default: 10).")
    p.add_argument("--json", action="store_true", help="Emit report as JSON instead of text.")
    p.add_argument("--verify-vault", action="store_true", help="Verify vault hash chain integrity (can be slow on big DBs).")
    return p.parse_args()


def safe_load_context(context_json: Optional[str]) -> Optional[Dict[str, Any]]:
    if not context_json:
        return None
    try:
        obj = json.loads(context_json)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def fetch_logs(db_path: str, cutoff_ts: str) -> List[Tuple[int, str, str, str, Optional[str], Optional[str]]]:
    """
    Returns rows:
      (id, timestamp, module, message, context_json, level?)
    level may be None if legacy schema.
    """
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()

        # Prefer modern schema with level + context_json
        try:
            cur.execute(
                """
                SELECT id, timestamp, module, message, context_json, level
                FROM event_logs
                WHERE timestamp >= ?
                ORDER BY id ASC
                """,
                (cutoff_ts,),
            )
            rows = cur.fetchall()
            # normalize into the expected tuple order
            return [(i, ts, mod, msg, ctx, lvl) for (i, ts, mod, msg, ctx, lvl) in rows]
        except sqlite3.Error:
            pass

        # Fallback: timestamp/module/message/context_json
        try:
            cur.execute(
                """
                SELECT id, timestamp, module, message, context_json
                FROM event_logs
                WHERE timestamp >= ?
                ORDER BY id ASC
                """,
                (cutoff_ts,),
            )
            rows = cur.fetchall()
            return [(i, ts, mod, msg, ctx, None) for (i, ts, mod, msg, ctx) in rows]
        except sqlite3.Error:
            pass

        # Legacy fallback: timestamp/module/message only
        cur.execute(
            """
            SELECT id, timestamp, module, message
            FROM event_logs
            WHERE timestamp >= ?
            ORDER BY id ASC
            """,
            (cutoff_ts,),
        )
        rows = cur.fetchall()
        return [(i, ts, mod, msg, None, None) for (i, ts, mod, msg) in rows]


def parse_threat_message(msg: str) -> Optional[Tuple[str, str]]:
    prefix = "Threat Detected: "
    if not msg.startswith(prefix):
        return None
    try:
        rest = msg[len(prefix):]
        threat_type, ip = rest.rsplit(" from ", 1)
        return threat_type.strip(), ip.strip()
    except ValueError:
        return None


def vault_stats(db_path: str) -> Dict[str, Any]:
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM data_vault;")
            total = int(cur.fetchone()[0])
            cur.execute("SELECT timestamp FROM data_vault ORDER BY timestamp DESC LIMIT 1;")
            last = cur.fetchone()
            return {"records": total, "last_timestamp": (last[0] if last else None)}
        except sqlite3.Error:
            return {"records": None, "last_timestamp": None}


def verify_vault_chain(db_path: str) -> bool:
    # lightweight chain verification based on your schema
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT record_id, timestamp, label, payload_sha256, prev_hash, record_hash
            FROM data_vault ORDER BY timestamp ASC;
            """
        )
        rows = cur.fetchall()

    prev = None
    import hashlib

    for record_id, ts, label, payload_sha, prev_hash, record_hash in rows:
        if prev_hash != prev:
            return False
        blob = json.dumps(
            {
                "record_id": record_id,
                "timestamp": ts,
                "label": label,
                "payload_sha256": payload_sha,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        expected = hashlib.sha256(blob).hexdigest()
        if expected != record_hash:
            return False
        prev = record_hash
    return True


def analyze_logs(rows: List[Tuple[int, str, str, str, Optional[str], Optional[str]]]) -> Dict[str, Any]:
    threats_by_ip: Dict[str, Counter] = defaultdict(Counter)
    threat_type_counter: Counter = Counter()

    total_threats = 0
    pending_actions = 0
    auto_executed = 0
    vetoed = 0

    first_ts: Optional[str] = None
    last_ts: Optional[str] = None

    sample_lines: List[Tuple[str, str, str]] = []

    for _id, ts, module, message, context_json, _level in rows:
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        if len(sample_lines) < 100:
            sample_lines.append((ts, module, message))

        ctx = safe_load_context(context_json)

        # Threat detection
        if module == "THREAT_INT":
            ip = None
            threat_type = None

            if ctx:
                ip = ctx.get("ip") or ctx.get("ip_source")
                threat_type = ctx.get("threat_type")

            if not (ip and threat_type):
                parsed = parse_threat_message(message)
                if parsed:
                    threat_type, ip = parsed

            if ip and threat_type:
                total_threats += 1
                threat_type_counter[threat_type] += 1
                threats_by_ip[ip][threat_type] += 1
            continue

        # Oversight actions
        if module == "OVERSIGHT":
            # Prefer structured context if you add it later, but keep string fallback.
            m = message.upper()
            if "PENDING:" in message or "ACTION STAGED" in m:
                pending_actions += 1
            elif "TIMEOUT -> AUTO-EXECUTING" in message or "AUTO-EXECUT" in m:
                auto_executed += 1
            elif "VETOED:" in message or "VETO" in m:
                vetoed += 1

    return {
        "total_threats": total_threats,
        "threat_type_counter": threat_type_counter,
        "threats_by_ip": threats_by_ip,
        "pending_actions": pending_actions,
        "auto_executed": auto_executed,
        "vetoed": vetoed,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "sample_lines": sample_lines,
    }


def print_report(analysis: Dict[str, Any], days: int, db_path: str, sample_limit: int, vault: Dict[str, Any], vault_ok: Optional[bool]) -> None:
    print()
    print(f"SHADOW-RUN STYLE REPORT (last {days} day(s))")
    print("=" * 60)
    print(f"Source DB      : {db_path}")
    if analysis["first_ts"] and analysis["last_ts"]:
        print(f"Time window    : {analysis['first_ts']}  ->  {analysis['last_ts']}")
    else:
        print("Time window    : No events in selected range.")

    print()
    print("THREAT SUMMARY")
    print("-" * 60)
    print(f"Total threats observed                 : {analysis['total_threats']}")
    print(f"Unique source IPs                      : {len(analysis['threats_by_ip'])}")
    print(f"Total recommendations (pending logged) : {analysis['pending_actions']}")
    print(f"Auto-executed equivalents              : {analysis['auto_executed']}")
    print(f"Operator vetoes recorded               : {analysis['vetoed']}")

    print()
    print("VAULT SUMMARY")
    print("-" * 60)
    print(f"Vault records                          : {vault.get('records')}")
    print(f"Vault last timestamp                    : {vault.get('last_timestamp')}")
    if vault_ok is not None:
        print(f"Vault chain integrity                   : {'OK' if vault_ok else 'FAILED'}")

    print()
    print("Threats by type:")
    if not analysis["threat_type_counter"]:
        print("  (none recorded)")
    else:
        for ttype, count in analysis["threat_type_counter"].most_common():
            print(f"  - {ttype}: {count}")

    print()
    print("Top source IPs:")
    if not analysis["threats_by_ip"]:
        print("  (none recorded)")
    else:
        ip_rank = []
        for ip, counter in analysis["threats_by_ip"].items():
            total = sum(counter.values())
            ip_rank.append((ip, total, counter))
        ip_rank.sort(key=lambda x: x[1], reverse=True)

        for ip, total, counter in ip_rank[:10]:
            breakdown = ", ".join(f"{ttype}={count}" for ttype, count in counter.most_common())
            print(f"  - {ip}: {total} event(s) [{breakdown}]")

    print()
    print(f"Sample log lines (up to {sample_limit}):")
    print("-" * 60)
    if not analysis["sample_lines"]:
        print("  (no log data)")
    else:
        for ts, module, msg in analysis["sample_lines"][:sample_limit]:
            print(f"[{ts}] [{module}] {msg}")

    print()
    print("End of report.")
    print()


def main() -> None:
    args = parse_args()

    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=args.days)
    cutoff_str = cutoff.isoformat(timespec="microseconds") + "Z"

    try:
        rows = fetch_logs(args.db_path, cutoff_str)
    except sqlite3.Error as exc:
        print(f"[ERROR] Failed to open or query DB '{args.db_path}': {exc}")
        return

    analysis = analyze_logs(rows)
    vstats = vault_stats(args.db_path)
    vault_ok = verify_vault_chain(args.db_path) if args.verify_vault else None

    if args.json:
        # Convert Counters/defaultdict to plain JSON-friendly structures
        out = {
            "db": args.db_path,
            "days": args.days,
            "window": {"first": analysis["first_ts"], "last": analysis["last_ts"]},
            "totals": {
                "threats": analysis["total_threats"],
                "unique_ips": len(analysis["threats_by_ip"]),
                "pending": analysis["pending_actions"],
                "auto_executed": analysis["auto_executed"],
                "vetoed": analysis["vetoed"],
            },
            "threats_by_type": dict(analysis["threat_type_counter"]),
            "top_ips": [
                {"ip": ip, "total": total, "breakdown": dict(counter)}
                for ip, total, counter in sorted(
                    ((ip, sum(c.values()), c) for ip, c in analysis["threats_by_ip"].items()),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10]
            ],
            "vault": {**vstats, "chain_ok": vault_ok},
            "samples": analysis["sample_lines"][: args.limit_samples],
        }
        print(json.dumps(out, indent=2, default=str))
        return

    print_report(analysis, args.days, args.db_path, args.limit_samples, vstats, vault_ok)


if __name__ == "__main__":
    main()