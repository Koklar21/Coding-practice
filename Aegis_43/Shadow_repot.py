import argparse
import datetime
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# -------------------------
# Option A: DB next to file
# -------------------------
try:
    DEFAULT_DB = str(Path(__file__).resolve().parent / "aegis_secure.db")
except NameError:
    DEFAULT_DB = str(Path.cwd() / "aegis_secure.db")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a shadow-mode style report from AEGIS event logs."
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        default=DEFAULT_DB,
        help=f"Path to SQLite DB (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="How many days back to include in the report (default: 7).",
    )
    parser.add_argument(
        "--limit-samples",
        type=int,
        default=10,
        help="Max number of sample log lines to print (default: 10).",
    )
    return parser.parse_args()


def fetch_logs(db_path: str, days: int) -> List[Tuple[int, str, str, str, Optional[str]]]:
    """
    Returns rows: (id, timestamp, module, message, context_json)
    """
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    cutoff_str = cutoff.isoformat()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # If context_json column doesn't exist in older DBs, this will throw.
    # We'll try modern schema first, then fallback.
    try:
        cursor.execute(
            """
            SELECT id, timestamp, module, message, context_json
            FROM event_logs
            WHERE timestamp >= ?
            ORDER BY id ASC
            """,
            (cutoff_str,),
        )
        rows = cursor.fetchall()
    except sqlite3.Error:
        cursor.execute(
            """
            SELECT id, timestamp, module, message
            FROM event_logs
            WHERE timestamp >= ?
            ORDER BY id ASC
            """,
            (cutoff_str,),
        )
        legacy = cursor.fetchall()
        rows = [(i, ts, mod, msg, None) for (i, ts, mod, msg) in legacy]

    conn.close()
    return rows


def parse_threat_message(msg: str) -> Optional[Tuple[str, str]]:
    # Format: "Threat Detected: {threat_type} from {ip}"
    prefix = "Threat Detected: "
    if not msg.startswith(prefix):
        return None
    try:
        rest = msg[len(prefix):]
        threat_type, ip = rest.rsplit(" from ", 1)
        return threat_type.strip(), ip.strip()
    except ValueError:
        return None


def safe_load_context(context_json: Optional[str]) -> Optional[Dict[str, Any]]:
    if not context_json:
        return None
    try:
        obj = json.loads(context_json)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def analyze_logs(rows: List[Tuple[int, str, str, str, Optional[str]]]) -> Dict[str, Any]:
    threats_by_ip: Dict[str, Counter] = defaultdict(Counter)
    threat_type_counter: Counter = Counter()
    total_threats = 0

    pending_actions = 0
    auto_executed = 0
    vetoed = 0

    first_ts: Optional[str] = None
    last_ts: Optional[str] = None

    sample_lines: List[Tuple[str, str, str]] = []

    for _id, ts, module, message, context_json in rows:
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        if len(sample_lines) < 100:
            sample_lines.append((ts, module, message))

        ctx = safe_load_context(context_json)

        # -----------------------
        # Threat detection: prefer structured context
        # -----------------------
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

        # -----------------------
        # Oversight actions
        # -----------------------
        if module == "OVERSIGHT":
            if "PENDING:" in message:
                pending_actions += 1
            elif "TIMEOUT -> AUTO-EXECUTING" in message:
                auto_executed += 1
            elif "VETOED:" in message:
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


def print_report(analysis: Dict[str, Any], days: int, db_path: str, sample_limit: int) -> None:
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

    try:
        rows = fetch_logs(args.db_path, args.days)
    except sqlite3.Error as exc:
        print(f"[ERROR] Failed to open or query DB '{args.db_path}': {exc}")
        return

    analysis = analyze_logs(rows)
    print_report(analysis, args.days, args.db_path, args.limit_samples)


if __name__ == "__main__":
    main()