#!/usr/bin/env python3
"""
whois_verify.py - WHOIS-based domain ownership verifier.

Requires:
    pip install python-whois

Usage:
    python whois_verify.py -d example.com --owner owners.txt
    python whois_verify.py -df domains.txt --owner owners.txt -o matched.txt
    python whois_verify.py -df domains.txt --owner owners.txt --rate 2.0 -v
"""

import argparse
import csv
import sys
import time
import re
from pathlib import Path
from datetime import datetime

try:
    import whois  # python-whois
except ImportError:
    print(
        "ERROR: 'python-whois' is not installed.\n"
        "       Run:  pip install python-whois",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RATE_LIMIT_SECONDS = 1.5
DEFAULT_CSV_OUT    = "whois_results.csv"


# ---------------------------------------------------------------------------
# WHOIS query wrapper
# ---------------------------------------------------------------------------

def whois_query(domain: str) -> dict:
    """
    Query WHOIS via python-whois and normalise the result into:
        org          - registrant / organisation name  (str)
        email        - registrant email(s)             (list[str])
        registrar    - registrar name                  (str)
        raw          - raw text response               (str)
        error        - error message on failure        (str)
    """
    result = {"org": "", "email": [], "registrar": "", "raw": "", "error": ""}

    try:
        w = whois.whois(domain)
    except whois.parser.PywhoisError as exc:
        result["error"] = f"WHOIS parse error: {exc}"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result

    # ---- org / registrant name ----
    for attr in ("organizations", "registrant_name", "name"):
        val = getattr(w, attr, None)
        if val:
            result["org"] = val.strip() if isinstance(val, str) else str(val).strip()
            break

    # ---- email(s) ----
    raw_emails = getattr(w, "emails", None) or getattr(w, "registrant_email", None)
    if raw_emails:
        if isinstance(raw_emails, list):
            result["email"] = [e.strip() for e in raw_emails if e]
        else:
            result["email"] = [raw_emails.strip()]

    # ---- registrar ----
    registrar = getattr(w, "registrar", None)
    if registrar:
        result["registrar"] = (
            registrar.strip() if isinstance(registrar, str) else str(registrar).strip()
        )

    # ---- raw text ----
    raw_text = getattr(w, "text", None)
    if raw_text:
        result["raw"] = raw_text if isinstance(raw_text, str) else "\n".join(raw_text)

    return result


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def match_owners(whois_data: dict, owner_terms: list) -> list:
    """
    Compare each owner term (substring, case-insensitive) against:
        - org   field  -> labelled 'orgname'
        - email fields -> labelled 'registrant email'

    Returns a deduplicated list of (field_label, matched_value) tuples.
    """
    matches = []

    org_n  = _normalize(whois_data.get("org", ""))
    emails = whois_data.get("email", [])

    for term in owner_terms:
        t = _normalize(term)
        if not t:
            continue

        if org_n and t in org_n:
            matches.append(("orgname", whois_data["org"]))

        for email in emails:
            if t in _normalize(email):
                matches.append(("registrant email", email))

    # deduplicate while preserving order
    seen, deduped = set(), []
    for item in matches:
        key = (item[0], _normalize(item[1]))
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    return deduped


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def read_lines(path: str) -> list:
    lines = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify domain ownership via WHOIS and match against known org/email identifiers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python whois_verify.py -d example.com --owner owners.txt
  python whois_verify.py -df domains.txt --owner owners.txt -o matched.txt
  python whois_verify.py -df domains.txt --owner owners.txt --rate 2.0 -v
        """,
    )

    domain_group = parser.add_mutually_exclusive_group(required=True)
    domain_group.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        help="Single domain to query.",
    )
    domain_group.add_argument(
        "-df", "--domain-file",
        metavar="FILE",
        help="File containing one domain per line.",
    )

    parser.add_argument(
        "--owner",
        required=True,
        metavar="FILE",
        help="File containing org names or registrant emails to match (one per line).",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help="If provided, write a plain list of matched domains to this file.",
    )
    parser.add_argument(
        "--csv-out",
        metavar="FILE",
        default=DEFAULT_CSV_OUT,
        help=f"CSV output file (default: {DEFAULT_CSV_OUT}).",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=RATE_LIMIT_SECONDS,
        metavar="SECONDS",
        help=f"Seconds to wait between WHOIS queries (default: {RATE_LIMIT_SECONDS}).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print raw WHOIS response for each domain.",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # --- domains ---
    if args.domain:
        domains = [args.domain.strip()]
    else:
        if not Path(args.domain_file).is_file():
            print(f"ERROR: domain file not found: {args.domain_file}", file=sys.stderr)
            sys.exit(1)
        domains = read_lines(args.domain_file)

    # --- owner terms ---
    if not Path(args.owner).is_file():
        print(f"ERROR: owner file not found: {args.owner}", file=sys.stderr)
        sys.exit(1)
    owner_terms = read_lines(args.owner)

    if not owner_terms:
        print("ERROR: owner file is empty.", file=sys.stderr)
        sys.exit(1)

    log(f"Domains to query : {len(domains)}")
    log(f"Owner terms      : {len(owner_terms)}")
    log(f"Rate limit       : {args.rate}s between queries")
    log(f"CSV output       : {args.csv_out}")
    if args.output:
        log(f"Matched-domain list -> {args.output}")

    matched_domains = []

    with open(args.csv_out, "w", newline="", encoding="utf-8") as csv_fh:
        writer = csv.writer(csv_fh)
        writer.writerow(["domain", "match"])   # header

        for idx, domain in enumerate(domains):
            domain = domain.strip()
            if not domain:
                continue

            log(f"[{idx + 1}/{len(domains)}] Querying {domain} ...")

            data = whois_query(domain)

            if data["error"]:
                log(f"  !! Error: {data['error']}")
            else:
                log(f"  org      : {data['org'] or '(none)'}")
                log(f"  emails   : {', '.join(data['email']) or '(none)'}")
                log(f"  registrar: {data['registrar'] or '(none)'}")

            if args.verbose and data["raw"]:
                print("\n--- RAW WHOIS ---", file=sys.stderr)
                print(data["raw"][:4000], file=sys.stderr)
                print("--- END RAW ---\n", file=sys.stderr)

            matches = match_owners(data, owner_terms)

            if matches:
                log(f"  MATCHED ({len(matches)} hit(s))")
                for field_label, value in matches:
                    writer.writerow([domain, f"<{field_label}>:{value}"])
                csv_fh.flush()
                matched_domains.append(domain)
            else:
                log("  - no match")

            # rate-limit: skip sleep after last domain
            if idx < len(domains) - 1:
                time.sleep(args.rate)

    # --- optional plain matched-domain file ---
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_fh:
            for d in matched_domains:
                out_fh.write(d + "\n")
        log(f"Wrote {len(matched_domains)} matched domain(s) -> {args.output}")

    log(f"Done. {len(matched_domains)}/{len(domains)} domain(s) matched.")
    log(f"Full results saved to -> {args.csv_out}")


if __name__ == "__main__":
    main()
