import argparse
import threading
import queue
import json
import signal
import sys
import os
from sublist3r import main as sublist3r_main
import dns.resolver

# Global control flags
STOP_FLAG = False
LOCK = threading.Lock()

STATE_FILE = "checkpoint.json"


def save_state(state):
    with LOCK:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return None


def signal_handler(sig, frame):
    global STOP_FLAG
    print("\n[!] Received interrupt. Saving progress...")
    STOP_FLAG = True


signal.signal(signal.SIGINT, signal_handler)


def resolve_domain(domain):
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except:
        return False


def bruteforce_subdomains(domain, wordlist):
    found = []
    for word in wordlist:
        if STOP_FLAG:
            break
        sub = f"{word}.{domain}"
        if resolve_domain(sub):
            print(f"[+] FOUND: {sub}")
            found.append(sub)
    return found


def passive_enum(domain):
    try:
        print(f"[*] Passive enum: {domain}")
        return sublist3r_main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    except Exception as e:
        print(f"[!] Sublist3r failed: {e}")
        return []


def worker(q, results, wordlist, max_depth, state):
    while not q.empty():
        if STOP_FLAG:
            break

        domain, depth = q.get()

        if domain in state["processed"]:
            q.task_done()
            continue

        print(f"[*] Processing: {domain} (depth={depth})")

        found = set()

        # Passive
        found.update(passive_enum(domain))

        # Bruteforce
        found.update(bruteforce_subdomains(domain, wordlist))

        with LOCK:
            state["processed"].append(domain)
            state["results"].extend(list(found))

        # Recursion
        if depth < max_depth:
            for sub in found:
                q.put((sub, depth + 1))

        save_state(state)
        q.task_done()


def main():
    parser = argparse.ArgumentParser(description="Advanced DNS Subdomain Enumerator")
    parser.add_argument("-d", help="Single domain")
    parser.add_argument("-dL", help="List of domains")
    parser.add_argument("-w", required=True, help="Wordlist")
    parser.add_argument("-o", default="output.txt", help="Output file")
    parser.add_argument("--max-depth", type=int, default=1)
    parser.add_argument("--threads", type=int, default=10)

    args = parser.parse_args()

    # Load wordlist
    with open(args.w) as f:
        wordlist = [line.strip() for line in f if line.strip()]

    # Load domains
    domains = []
    if args.d:
        domains.append(args.d)
    elif args.dL:
        with open(args.dL) as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        print("[-] Provide -d or -dL")
        sys.exit(1)

    # Resume state
    state = load_state()
    if not state:
        state = {
            "processed": [],
            "results": []
        }

    q = queue.Queue()

    for d in domains:
        q.put((d, 0))

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, state["results"], wordlist, args.max_depth, state))
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass

    print("\n[+] Writing output...")
    with open(args.o, "w") as f:
        for r in set(state["results"]):
            f.write(r + "\n")

    print("[+] Done.")


if __name__ == "__main__":
    main()
