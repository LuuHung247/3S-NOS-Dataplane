#!/usr/bin/env python3
"""
08-verify-policy.py — Verify Zero Trust microsegmentation enforcement
======================================================================
Chạy từ: dis@gns3vm
Chức năng: Test tất cả flows theo policy matrix, verify ALLOW và DENY đều đúng.

Expected results sau khi apply policy:
  ALLOW: WEB → APP       (web gọi backend API)
  ALLOW: APP → DB        (app query database)
  ALLOW: MGT → WEB       (management truy cập)
  ALLOW: MGT → DB        (management truy cập)
  ALLOW: MGT → APP       (management truy cập)
  DENY:  WEB → DB        (ZERO TRUST: web không truy cập DB trực tiếp)
  DENY:  WEB → MGT       (web không truy cập management)
  DENY:  DB  → WEB       (DB không gửi ra ngoài)
  DENY:  DB  → APP       (DB không gửi ra ngoài)
  DENY:  DB  → MGT       (DB không gửi ra ngoài)
  DENY:  APP → WEB       (app không gọi ngược web)
  DENY:  APP → MGT       (app không truy cập management)
"""

import socket
import telnetlib
import time
import sys
import random

# Alpine hosts
ALPINES = {
    "WEB": {"port": 5008, "ip": "10.1.100.10"},
    "DB":  {"port": 5011, "ip": "10.1.200.10"},
    "APP": {"port": 5014, "ip": "10.2.100.10"},
    "MGT": {"port": 5016, "ip": "10.2.50.10"},
}

# Policy matrix: (source, dest, expected "ALLOW" or "DENY", reason)
POLICY_TESTS = [
    ("WEB", "APP", "ALLOW", "Web calls backend API"),
    ("WEB", "DB",  "DENY",  "Zero Trust: no direct web-to-db"),
    ("WEB", "MGT", "DENY",  "Web cannot reach management"),
    ("APP", "DB",  "ALLOW", "App queries database"),
    ("APP", "WEB", "DENY",  "App should not call back to web"),
    ("APP", "MGT", "DENY",  "App cannot reach management"),
    ("DB",  "WEB", "DENY",  "DB cannot initiate outbound"),
    ("DB",  "APP", "DENY",  "DB cannot initiate outbound"),
    ("DB",  "MGT", "DENY",  "DB cannot initiate outbound"),
    ("MGT", "WEB", "ALLOW", "Management full access"),
    ("MGT", "DB",  "ALLOW", "Management full access"),
    ("MGT", "APP", "ALLOW", "Management full access"),
]


def alpine_ping(port, target_ip, count=2, timeout=2):
    """Ping from Alpine host via telnet console, return (sent, received)."""
    sentinel = f"DONE_{random.randint(10000,99999)}"
    try:
        tn = telnetlib.Telnet("127.0.0.1", port, timeout=5)
    except (ConnectionRefusedError, OSError):
        return 0, 0

    def drain(wait=0.5):
        time.sleep(wait)
        try:
            return tn.read_very_eager().decode(errors="ignore")
        except EOFError:
            return ""

    def read_until_sentinel(marker, max_wait=20):
        out = ""
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                d = tn.read_very_eager().decode(errors="ignore")
                out += d
                if marker in out:
                    break
            except EOFError:
                break
            time.sleep(0.3)
        return out

    # Ctrl+C to break any stuck process, then drain
    tn.write(b"\x03")
    drain(0.5)
    tn.write(b"\n")
    r = drain(1.0)
    if "login:" in r:
        tn.write(b"root\n")
        drain(2.0)
    tn.write(b"\n")
    drain(0.5)

    # Ping + sentinel (wait for sentinel on its own line, not in command echo)
    tn.write(f"ping {target_ip} -c {count} -W {timeout}; echo {sentinel}\n".encode())
    time.sleep(0.5)
    r = read_until_sentinel(f"\n{sentinel}", max_wait=count * (timeout + 1) + 5)
    tn.get_socket().close()

    for line in r.split("\n"):
        if "packets transmitted" in line or "packet loss" in line:
            parts = line.split(",")
            try:
                sent = int(parts[0].strip().split()[0])
                recv = int(parts[1].strip().split()[0])
                return sent, recv
            except (IndexError, ValueError):
                pass
    return 0, 0


def main():
    print("=" * 70)
    print("  Zero Trust Microsegmentation — Policy Verification")
    print("=" * 70)
    print()
    print(f"  {'Source':5s} → {'Dest':5s}  {'Expected':8s}  {'Result':8s}  Reason")
    print(f"  {'-'*5}   {'-'*5}  {'-'*8}  {'-'*8}  {'-'*35}")

    correct = 0
    wrong = 0
    details = []

    for src_name, dst_name, expected, reason in POLICY_TESTS:
        src = ALPINES[src_name]
        dst = ALPINES[dst_name]

        sent, recv = alpine_ping(src["port"], dst["ip"])
        actual = "ALLOW" if recv > 0 else "DENY"
        match = actual == expected

        if match:
            correct += 1
            icon = "OK"
        else:
            wrong += 1
            icon = "WRONG"
            details.append(f"{src_name}→{dst_name}: expected {expected}, got {actual}")

        print(f"  {src_name:5s} → {dst_name:5s}  {expected:8s}  {actual:8s}  {icon:5s}  {reason}")

    # Summary
    print()
    print("=" * 70)
    total = correct + wrong
    print(f"  Results: {correct}/{total} correct, {wrong}/{total} wrong")

    if wrong == 0:
        print("  Status: ZERO TRUST POLICY FULLY ENFORCED!")
        print()
        print("  Key demonstration points:")
        print("    1. WEB→APP allowed (legitimate API calls)")
        print("    2. WEB→DB BLOCKED (microsegmentation prevents direct DB access)")
        print("    3. APP→DB allowed (only app tier can query database)")
        print("    4. DB cannot initiate ANY outbound connections")
        print("    5. MGT has full access (administrative override)")
    else:
        print("  Status: POLICY NOT FULLY ENFORCED")
        print("  Issues:")
        for d in details:
            print(f"    - {d}")
        print()
        print("  Fix: python3 07-apply-policy.py apply")

    print("=" * 70)
    return 0 if wrong == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
