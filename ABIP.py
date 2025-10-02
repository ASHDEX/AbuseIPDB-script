#!/usr/bin/env python3


import sys, time, ipaddress
from datetime import datetime, timezone

try:
    import requests
except ModuleNotFoundError:
    sys.stderr.write(
        "Missing 'requests'. In OnlineGDB, open terminal and run:\n"
        "  pip install requests\n\n"
    )
    raise

API_BASE = "https://api.abuseipdb.com/api/v2"
CHECK_ENDPOINT = f"{API_BASE}/check"

# Your API key
API_KEY = ""

#  Default IPs
DEFAULT_IPS = "46.175.24.247 8.8.8.8 1.1.1.1"

MAX_AGE_DAYS = 90
REQUEST_DELAY = 0.35


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except:
        return False


def parse_ips(s: str) -> list[str]:
    tokens = s.replace(",", " ").split()
    seen, out = set(), []
    for t in tokens:
        if is_valid_ip(t) and t not in seen:
            seen.add(t)
            out.append(t.strip())
    return out


def abuse_check(ip: str) -> dict:
    if not API_KEY or API_KEY.startswith("PASTE_"):
        raise RuntimeError("Please set your AbuseIPDB API key in API_KEY")
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS}
    resp = requests.get(CHECK_ENDPOINT, headers=headers, params=params, timeout=20)
    if resp.status_code == 429:
        retry = int(resp.headers.get("Retry-After", "5"))
        print(f"[429] rate limit — sleeping {retry}s", file=sys.stderr)
        time.sleep(retry)
        resp = requests.get(CHECK_ENDPOINT, headers=headers, params=params, timeout=20)
    resp.raise_for_status()
    return resp.json()


def flatten(payload: dict) -> dict:
    d = payload.get("data", {})
    return {
        "IP": d.get("ipAddress"),
        "Score": str(d.get("abuseConfidenceScore")),
        "Reports": str(d.get("totalReports")),
        "Users": str(d.get("numDistinctUsers")),
        "Last Reported": str(d.get("lastReportedAt")),
        "Country": str(d.get("countryCode")),
        "ISP": str(d.get("isp")),
        "Domain": str(d.get("domain")),
    }


def print_table(rows: list[dict]):
    headers = ["IP", "Score", "Reports", "Users", "Last Reported", "Country", "ISP", "Domain"]

    # calculate column widths
    col_widths = {h: len(h) for h in headers}
    for row in rows:
        for h in headers:
            col_widths[h] = max(col_widths[h], len(str(row.get(h, ""))))

    # helper to format a row
    def fmt_row(rowdict):
        return " | ".join(str(rowdict.get(h, "")).ljust(col_widths[h]) for h in headers)

    # print header
    print("-" * (sum(col_widths.values()) + 3 * (len(headers) - 1)))
    print(fmt_row({h: h for h in headers}))
    print("-" * (sum(col_widths.values()) + 3 * (len(headers) - 1)))

    # print rows
    for row in rows:
        print(fmt_row(row))

    print("-" * (sum(col_widths.values()) + 3 * (len(headers) - 1)))


def main():
    ips = parse_ips(DEFAULT_IPS)
    if not ips:
        print("No valid IPs. Edit DEFAULT_IPS.")
        sys.exit(1)

    results = []
    for i, ip in enumerate(ips, 1):
        try:
            payload = abuse_check(ip)
            results.append(flatten(payload))
        except Exception as e:
            results.append({
                "IP": ip,
                "Score": "ERROR",
                "Reports": "",
                "Users": "",
                "Last Reported": "",
                "Country": "",
                "ISP": "",
                "Domain": str(e),
            })
        if i < len(ips):
            time.sleep(REQUEST_DELAY)

    print_table(results)


if __name__ == "__main__":
    main()
