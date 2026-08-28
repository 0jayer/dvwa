"""
detect_sqli.py

Scans a web server access log (Apache Combined Log Format) and flags
requests that look like SQL Injection attempts, based on common
signature patterns.

Usage:
    python detect_sqli.py dvwa_access.log
"""

import re
import sys
import urllib.parse

# Each pattern is a (name, regex, severity) tuple.
# Patterns are matched against the DECODED request line (spaces, quotes,
# etc. restored) so URL-encoding doesn't hide anything from us.
SQLI_SIGNATURES = [
    ("UNION SELECT",         r"union\s+select",              "HIGH"),
    ("Information schema access", r"information_schema",     "HIGH"),
    ("Always-true condition", r"'\s*or\s*'?1'?\s*=\s*'?1",    "HIGH"),
    ("Comment sequence",     r"(--\s|#|\/\*)",                "MEDIUM"),
    ("Single quote in param", r"=\s*[\d\w]*'",                "LOW"),
    ("ORDER BY probing",     r"order\s+by\s+\d+",             "MEDIUM"),
]

LOG_LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+)'
)


def decode_request(path: str) -> str:
    """URL-decode a request path/query string, and normalise '+' to space."""
    return urllib.parse.unquote_plus(path)


def scan_log(filepath: str):
    findings = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            match = LOG_LINE_RE.search(line)
            if not match:
                continue  # skip malformed / non-request lines (e.g. 408s)

            raw_path = match.group("path")
            decoded_path = decode_request(raw_path)

            matched_signatures = []
            for name, pattern, severity in SQLI_SIGNATURES:
                if re.search(pattern, decoded_path, re.IGNORECASE):
                    matched_signatures.append((name, severity))

            if matched_signatures:
                # Overall severity = highest severity among matches
                severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
                top_severity = max(
                    matched_signatures, key=lambda m: severity_order[m[1]]
                )[1]

                findings.append({
                    "line_num": line_num,
                    "ip": match.group("ip"),
                    "time": match.group("time"),
                    "decoded_path": decoded_path,
                    "signatures": matched_signatures,
                    "severity": top_severity,
                })

    return findings


def print_report(findings):
    if not findings:
        print("No suspicious SQLi patterns found.")
        return

    print(f"Found {len(findings)} suspicious request(s):\n")
    print("=" * 80)

    for f in findings:
        sig_names = ", ".join(name for name, _ in f["signatures"])
        print(f"[{f['severity']}] Line {f['line_num']} | {f['time']} | {f['ip']}")
        print(f"  Request : {f['decoded_path']}")
        print(f"  Matched : {sig_names}")
        print("-" * 80)

    # Simple summary counts
    from collections import Counter
    severity_counts = Counter(f["severity"] for f in findings)
    print("\nSummary:")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if sev in severity_counts:
            print(f"  {sev}: {severity_counts[sev]}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_sqli.py <access_log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    results = scan_log(log_file)
    print_report(results)