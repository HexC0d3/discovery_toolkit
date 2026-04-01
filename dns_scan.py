import argparse
import json
import csv
import whois
import dns.resolver
from urllib.parse import urlparse

# ---------------- DNS FUNCTIONS ---------------- #

def get_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def get_ns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [str(r.target).rstrip('.') for r in answers]
    except:
        return []

def get_a_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [r.address for r in answers]
    except:
        return []

# ---------------- WHOIS FUNCTION ---------------- #

def get_whois(domain):
    try:
        w = whois.whois(domain)

        registrant = None
        org = None

        if isinstance(w, dict):
            registrant = w.get("name")
            org = w.get("org")

        # Clean redacted values
        def is_valid(val):
            if not val:
                return False
            val = str(val).lower()
            return "redact" not in val and "privacy" not in val

        registrant_valid = registrant if is_valid(registrant) else None
        org_valid = org if is_valid(org) else None

        return registrant_valid or org_valid

    except:
        return None

# ---------------- CORE PROCESS ---------------- #

def process_domain(domain):
    data = {}

    data['domain'] = domain
    data['mx'] = get_mx(domain)
    data['ns'] = get_ns(domain)
    data['a_records'] = get_a_records(domain)
    data['registrant'] = get_whois(domain)

    return data

# ---------------- FILE HANDLING ---------------- #

def load_domains(args):
    domains = []

    if args.d:
        domains.append(args.d)

    if args.dL:
        with open(args.dL, 'r') as f:
            domains.extend([line.strip() for line in f if line.strip()])

    return list(set(domains))

def save_outputs(results, output_prefix):
    json_file = output_prefix + ".json"
    csv_file = output_prefix + ".csv"

    # JSON
    with open(json_file, 'w') as f:
        json.dump(results, f, indent=4)

    # CSV
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "mx", "ns", "registrant"])

        for r in results:
            writer.writerow([
                r['domain'],
                r['mx'],
                ";".join(r['ns']),
                r['registrant']
            ])

    print(f"[+] Saved JSON: {json_file}")
    print(f"[+] Saved CSV : {csv_file}")

# ---------------- INTERACTIVE FILTER ---------------- #

def extract_parent_ns(ns):
    try:
        parts = ns.split('.')
        return ".".join(parts[-2:])
    except:
        return ns

def interactive_shell(results):
    print("\n[+] Entering interactive mode")

    while True:
        print("\nFilter options:")
        print("1. By Name Server")
        print("2. By Registrar (Registrant)")
        print("3. By NS Parent Domain")
        print("4. Show All")
        print("5. Exit")

        choice = input("Select: ").strip()

        if choice == "1":
            ns_filter = input("Enter NS: ").strip()
            filtered = [r for r in results if ns_filter in r['ns']]
        
        elif choice == "2":
            reg_filter = input("Enter registrant keyword: ").lower()
            filtered = [
                r for r in results 
                if r['registrant'] and reg_filter in r['registrant'].lower()
            ]

        elif choice == "3":
            parent = input("Enter parent domain (e.g., cloudflare.com): ").strip()
            filtered = [
                r for r in results 
                if any(parent in extract_parent_ns(ns) for ns in r['ns'])
            ]

        elif choice == "4":
            filtered = results

        elif choice == "5":
            break

        else:
            print("Invalid choice")
            continue

        print("\n--- Results ---")
        for r in filtered:
            print(f"{r['domain']} | MX: {r['mx']} | NS: {r['ns']} | REG: {r['registrant']}")

# ---------------- MAIN ---------------- #

def main():
    parser = argparse.ArgumentParser(description="Domain intelligence tool")

    parser.add_argument("-d", help="Single domain")
    parser.add_argument("-dL", help="File with domains")
    parser.add_argument("-o", help="Output file prefix", default="output")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")

    args = parser.parse_args()

    domains = load_domains(args)

    if not domains:
        print("[-] No domains provided")
        return

    results = []

    for d in domains:
        print(f"[+] Processing {d}")
        results.append(process_domain(d))

    save_outputs(results, args.o)

    if args.interactive:
        interactive_shell(results)

if __name__ == "__main__":
    main()
