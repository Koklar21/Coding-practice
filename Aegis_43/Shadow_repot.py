import argparse
import datetime
import sqlite3
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional


DEFAULT_DB = "aegis_secure.db"


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


def fetch_logs(
    db_path: str, days: int
) -> List[Tuple[int, str, str, str]]:
    """
    Returns rows: (id, timestamp, module, message)
    """
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    cutoff_str = cutoff.isoformat()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, module, message
        FROM event_logs
        WHERE timestamp >= ?
        ORDER BY id ASC
        """,
        (cutoff_str,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def parse_threat_message(msg: str) -> Optional[Tuple[str, str]]:
    # Format: "Threat Detected: {threat_type} from {ip}"
    prefix = "Threat Detected: "
    if not msg.startswith(prefix):
        return None
    try:
        rest = msg[len(prefix) :]
        # split from the right on " from "
        threat_type, ip = rest.rsplit(" from ", 1)
        return threat_type.strip(), ip.strip()
    except ValueError:
        return None


def extract_ip_from_description(desc: str) -> Optional[str]:
    # Expected: "Firewall Ban for {ip}"
    prefix = "Firewall Ban for "
    if desc.startswith(prefix):
        return desc[len(prefix) :].strip()
    return None


def extract_ip_from_action_id(action_id: str) -> Optional[str]:
    # Expected: "BLOCK-203-0-113-88" -> "203.0.113.88"
    prefix = "BLOCK-"
    if not action_id.startswith(prefix):
        return None
    body = action_id[len(prefix) :]
    parts = body.split("-")
    if len(parts) < 4:
        return None
    return ".".join(parts)


def analyze_logs(
    rows: List[Tuple[int, str, str, str]]
) -> Dict[str, any]:
    threats_by_ip: Dict[str, Counter] = defaultdict(Counter)
    threat_type_counter: Counter = Counter()
    total_threats = 0

    pending_actions = 0
    auto_executed = 0
    vetoed = 0

    first_ts: Optional[str] = None
    last_ts: Optional[str] = None

    sample_lines: List[Tuple[str, str, str]] = []

    for _id, ts, module, message in rows:
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        # Collect some sample lines for the tail of the report
        if len(sample_lines) < 100:  # cap to avoid stupid amounts
            sample_lines.append((ts, module, message))

        # Threat detection
        parsed = parse_threat_message(message)
        if parsed:
            threat_type, ip = parsed
            total_threats += 1
            threat_type_counter[threat_type] += 1
            threats_by_ip[ip][threat_type] += 1
            continue

        # Oversight actions
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


def print_report(analysis: Dict[str, any], days: int, db_path: str, sample_limit: int):
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
    print(f"Total threats observed      : {analysis['total_threats']}")
    print(f"Unique source IPs           : {len(analysis['threats_by_ip'])}")
    print(
        f"Total recommendations (pending actions logged): {analysis['pending_actions']}"
    )
    print(f"Auto-executed equivalents   : {analysis['auto_executed']}")
    print(f"Operator vetoes recorded    : {analysis['vetoed']}")

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
        # rank IPs by total events
        ip_rank = []
        for ip, counter in analysis["threats_by_ip"].items():
            total = sum(counter.values())
            ip_rank.append((ip, total, counter))
        ip_rank.sort(key=lambda x: x[1], reverse=True)

        for ip, total, counter in ip_rank[:10]:
            breakdown = ", ".join(
                f"{ttype}={count}" for ttype, count in counter.most_common()
            )
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


def main():
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
