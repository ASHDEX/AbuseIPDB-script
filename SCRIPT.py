#!/usr/bin/env python3
"""
abuse_bulk_check.py

Bulk IP reputation checker for AbuseIPDB.

Features:
- Read IPs from a file (1 per line; commas/spaces tolerated).
- Validate IPs.
- Query /api/v2/check with maxAgeInDays (+ optional verbose).
- Handle 429 rate-limits via Retry-After and polite inter-request delay.
- SQLite cache so repeated runs within TTL skip API calls.
- Outputs:
    1) <outprefix>.csv       (flat fields)
    2) <outprefix>.jsonl     (full JSON payloads per IP, if available)
    3) <outprefix>_summary.csv (country counts & avg scores)
"""

import os
import sys
import csv
import json
import time
import math
import argparse
import sqlite3
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict

import requests

API_BASE = "https://api.abuseipdb.com/api/v2"
CHECK_ENDPOINT = f"{API_BASE}/check"

# ---------- Helpers ----------
def is_valid_ip(s: str) -> bool:
    s = s.strip()
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def load_api_key(cli_key: str | None) -> str:
    key = cli_key or os.getenv("ABUSEIPDB_KEY")
    if not key:
        raise RuntimeError("No API key. Provide --api-key or set ABUSEIPDB_KEY in env.")
    return key.strip()

def read_ips(path: str) -> list[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    ips = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            # allow commas/spaces/newlines
            parts = line.replace(",", " ").split()
            for p in parts:
                if p and is_valid_ip(p):
                    ips.append(p)
    # de-dup in order
    seen = set()
    uniq = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq

# ---------- SQLite cache ----------
def db_connect(db_path: str):
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def db_init(con: sqlite3.Connection):
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ipAddress TEXT NOT NULL,
            payload_json TEXT,            -- full JSON payload as string
            abuseConfidenceScore INTEGER,
            totalReports INTEGER,
            numDistinctUsers INTEGER,
            lastReportedAt TEXT,
            countryCode TEXT,
            usageType TEXT,
            isp TEXT,
            domain TEXT,
            hostnames TEXT,
            checkedAt TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_ip_time ON ip_checks (ipAddress, checkedAt)")
    con.commit()

def cache_lookup(con: sqlite3.Connection, ip: str, ttl_hours: int) -> sqlite3.Row | None:
    since = datetime.utcnow() - timedelta(hours=ttl_hours)
    cur = con.execute(
        "SELECT * FROM ip_checks WHERE ipAddress=? AND datetime(checkedAt) >= ? ORDER BY datetime(checkedAt) DESC LIMIT 1",
        (ip, since.isoformat(timespec="seconds"))
    )
    return cur.fetchone()

def cache_insert(con: sqlite3.Connection, row: dict, payload: dict):
    con.execute("""
        INSERT INTO ip_checks (
            ipAddress, payload_json, abuseConfidenceScore, totalReports, numDistinctUsers,
            lastReportedAt, countryCode, usageType, isp, domain, hostnames, checkedAt
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        row.get("ipAddress"),
        json.dumps(payload, ensure_ascii=False),
        row.get("abuseConfidenceScore"),
        row.get("totalReports"),
        row.get("numDistinctUsers"),
        row.get("lastReportedAt"),
        row.get("countryCode"),
        row.get("usageType"),
        row.get("isp"),
        row.get("domain"),
        row.get("hostnames"),
        datetime.utcnow().isoformat(timespec="seconds")
    ))
    con.commit()

# ---------- AbuseIPDB ----------
def abuse_check(api_key: str, ip: str, max_age_days: int, verbose: bool, timeout: int = 20) -> dict:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    if verbose:
        params["verbose"] = ""
    resp = requests.get(CHECK_ENDPOINT, headers=headers, params=params, timeout=timeout)
    # If rate-limited, honor Retry-After then retry once
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "5"))
        print(f"[429] Rate limit—retrying after {retry_after}s ...", flush=True)
        time.sleep(retry_after)
        resp = requests.get(CHECK_ENDPOINT, headers=headers, params=params, timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def flatten_payload(payload: dict) -> OrderedDict:
    d = payload.get("data", {})
    row = OrderedDict()
    row["ipAddress"] = d.get("ipAddress")
    row["isPublic"] = d.get("isPublic")
    row["ipVersion"] = d.get("ipVersion")
    row["abuseConfidenceScore"] = d.get("abuseConfidenceScore")
    row["totalReports"] = d.get("totalReports")
    row["numDistinctUsers"] = d.get("numDistinctUsers")
    row["lastReportedAt"] = d.get("lastReportedAt")
    row["countryCode"] = d.get("countryCode")
    row["usageType"] = d.get("usageType")
    row["isp"] = d.get("isp")
    row["domain"] = d.get("domain")
    row["hostnames"] = ",".join(d.get("hostnames", []) or [])
    return row

# ---------- Main logic ----------
def process_ips(
    api_key: str,
    ips: list[str],
    max_age_days: int,
    verbose: bool,
    outprefix: str,
    delay: float,
    retry_failures: int,
    cache_ttl_hours: int,
    db_path: str
):
    con = db_connect(db_path)
    db_init(con)

    csv_rows: list[OrderedDict] = []
    errors: list[dict] = []

    jsonl_path = f"{outprefix}.jsonl"
    csv_path = f"{outprefix}.csv"
    summary_path = f"{outprefix}_summary.csv"

    # open JSONL early (append mode so partial progress is saved)
    jsonl_fh = open(jsonl_path, "a", encoding="utf-8")

    total = len(ips)
    for idx, ip in enumerate(ips, 1):
        # progress line
        print(f"[{idx}/{total}] {ip} ...", end="", flush=True)

        # cache?
        cached = cache_lookup(con, ip, cache_ttl_hours)
        if cached:
            payload = json.loads(cached["payload_json"]) if cached["payload_json"] else None
            if payload:
                flat = flatten_payload(payload)
                csv_rows.append(flat)
                jsonl_fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
                print(" (cache)")
                # small delay to be polite anyway
                if idx < total and delay > 0:
                    time.sleep(delay / 4)
                continue

        # fetch with limited retries on network errors
        attempt = 0
        while True:
            try:
                payload = abuse_check(api_key, ip, max_age_days, verbose)
                break
            except requests.HTTPError as e:
                text = getattr(e.response, "text", "")
                err = f"HTTP {e.response.status_code}: {text[:200]}"
                attempt += 1
                if attempt > retry_failures or e.response.status_code == 400:
                    errors.append({"ip": ip, "error": err})
                    print(f" ERROR ({err})")
                    payload = None
                    break
                # backoff
                sleep_for = min(30, 2 ** attempt)
                print(f" RETRY {attempt} ({err}). Sleeping {sleep_for}s ...", end="", flush=True)
                time.sleep(sleep_for)
            except Exception as e:
                attempt += 1
                if attempt > retry_failures:
                    errors.append({"ip": ip, "error": str(e)})
                    print(f" ERROR ({e})")
                    payload = None
                    break
                sleep_for = min(30, 2 ** attempt)
                print(f" RETRY {attempt} ({e}). Sleeping {sleep_for}s ...", end="", flush=True)
                time.sleep(sleep_for)

        if payload:
            flat = flatten_payload(payload)
            csv_rows.append(flat)
            jsonl_fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
            cache_insert(con, flat, payload)
            print(" ok")
        # polite delay
        if idx < total and delay > 0:
            time.sleep(delay)

    jsonl_fh.close()

    # write CSV (flat fields)
    if csv_rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=csv_rows[0].keys())
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"→ Wrote CSV: {csv_path}")

        # summary by country
        by_cc = defaultdict(list)
        for r in csv_rows:
            cc = r.get("countryCode") or "??"
            try:
                score = float(r.get("abuseConfidenceScore") or 0)
            except Exception:
                score = 0.0
            by_cc[cc].append(score)

        with open(summary_path, "w", newline="", encoding="utf-8") as sf:
            w = csv.writer(sf)
            w.writerow(["countryCode", "count", "avgAbuseConfidenceScore"])
            for cc, scores in sorted(by_cc.items(), key=lambda kv: len(kv[1]), reverse=True):
                avg = round(sum(scores) / len(scores), 2) if scores else 0.0
                w.writerow([cc, len(scores), avg])
        print(f"→ Wrote summary: {summary_path}")

    # error report
    if errors:
        err_path = f"{outprefix}_errors.jsonl"
        with open(err_path, "w", encoding="utf-8") as ef:
            for e in errors:
                ef.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"→ Wrote errors: {err_path} ({len(errors)} issues)")

def main():
    p = argparse.ArgumentParser(description="Bulk IP reputation check via AbuseIPDB")
    p.add_argument("-f", "--file", required=True, help="Path to file of IPs (one per line; commas/spaces allowed)")
    p.add_argument("--api-key", help="AbuseIPDB API key (or set ABUSEIPDB_KEY env var)")
    p.add_argument("--max-age", type=int, default=90, help="maxAgeInDays for AbuseIPDB (default 90)")
    p.add_argument("--verbose", action="store_true", help="Request verbose payload")
    p.add_argument("--out", default="abuse_results", help="Output file prefix (default abuse_results)")
    p.add_argument("--delay", type=float, default=0.35, help="Seconds to sleep between requests (default 0.35)")
    p.add_argument("--retries", type=int, default=2, help="Retries on failures excluding 400 (default 2)")
    p.add_argument("--cache-ttl", type=int, default=24, help="Cache TTL in hours (default 24)")
    p.add_argument("--db", default="abuse_cache.sqlite3", help="SQLite DB path (default abuse_cache.sqlite3)")
    args = p.parse_args()

    try:
        api_key = load_api_key(args.api_key)
    except RuntimeError as e:
        print("ERROR:", e)
        sys.exit(1)

    ips = read_ips(args.file)
    if not ips:
        print("No valid IPs found in input.")
        sys.exit(0)

    print(f"Loaded {len(ips)} unique, valid IPs from {args.file}")
    process_ips(
        api_key=api_key,
        ips=ips,
        max_age_days=args.max_age,
        verbose=args.verbose,
        outprefix=args.out,
        delay=args.delay,
        retry_failures=args.retries,
        cache_ttl_hours=args.cache_ttl,
        db_path=args.db
    )

if __name__ == "__main__":
    main()
