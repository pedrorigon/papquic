#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
from typing import List

DEFAULT_OPENSSL = "/app/openssl-3.6.0/apps/openssl"

def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "")

def parse_list_output(s: str) -> List[str]:
    out, seen = [], set()
    for raw in s.splitlines():
        t = raw.strip()
        if not t:
            continue
        if t.lower().startswith((
            "providers:", "cipher", "mac", "message",
            "algorithms:", "loaded providers"
        )):
            continue
        if t.startswith("{"):
            m = re.search(r"\{([^}]*)\}", t)
            if m:
                parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
                if parts:
                    cand = parts[-1]
                    if cand not in seen:
                        seen.add(cand); out.append(cand)
            continue
        cand = t.split()[0].strip(",{}")
        if cand and cand != "@" and cand not in seen:
            seen.add(cand); out.append(cand)
    return out

def main():
    ap = argparse.ArgumentParser(description="List available KEM/groups and signature algorithms via OpenSSL.")
    ap.add_argument("--openssl", default=DEFAULT_OPENSSL, help="Path to openssl binary inside container")
    ap.add_argument("--format", choices=["plain", "json"], default="plain", help="Output format")
    args = ap.parse_args()

    # groups: try -tls-groups then fallback to -groups
    rc, out = run([args.openssl, "list", "-tls-groups"])
    if rc != 0 or not out.strip():
        rc, out = run([args.openssl, "list", "-groups"])
    groups = parse_list_output(out)

    # signatures
    _, outs = run([args.openssl, "list", "-signature-algorithms"])
    sigs = parse_list_output(outs)

    if args.format == "json":
        print(json.dumps({
            "groups": groups,
            "groups_count": len(groups),
            "signatures": sigs,
            "signatures_count": len(sigs),
        }, indent=2))
    else:
        print("=== KEM / Groups ===")
        print(f"count: {len(groups)}")
        for g in groups:
            print(g)
        print("\n=== Signature Algorithms ===")
        print(f"count: {len(sigs)}")
        for s in sigs:
            print(s)

if __name__ == "__main__":
    main()

