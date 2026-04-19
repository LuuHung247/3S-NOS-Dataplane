#!/usr/bin/env python3
"""
06-verify.py — Kiểm tra full connectivity matrix của DC fabric
================================================================
Chạy từ: dis@gns3vm
Chức năng: Ping giữa tất cả Alpine hosts để verify east-west routing.

Connectivity matrix cần đạt:
  Same-leaf:
    Alpine-1 (WEB) ↔ Alpine-2 (DB)   trên LEAF-1
    Alpine-3 (APP) ↔ Alpine-5 (MGT)  trên LEAF-2

  Cross-leaf (qua SPINE):
    Alpine-1 (WEB) ↔ Alpine-3 (APP)
    Alpine-1 (WEB) ↔ Alpine-5 (MGT)
    Alpine-2 (DB)  ↔ Alpine-3 (APP)
    Alpine-2 (DB)  ↔ Alpine-5 (MGT)
"""

import socket
import telnetlib
import time
import sys

# Alpine console ports và IP addresses
ALPINES = {
    "Alpine-1 (WEB)": {"port": 5008, "ip": "10.1.100.10"},
    "Alpine-2 (DB)":  {"port": 5011, "ip": "10.1.200.10"},
    "Alpine-3 (APP)": {"port": 5014, "ip": "10.2.100.10"},
    "Alpine-5 (MGT)": {"port": 5016, "ip": "10.2.50.10"},
}

# Test matrix: (source, target, type)
TESTS = [
    # Same-leaf
    ("Alpine-1 (WEB)", "Alpine-2 (DB)",  "same-leaf"),
    ("Alpine-3 (APP)", "Alpine-5 (MGT)", "same-leaf"),
    # Cross-leaf
    ("Alpine-1 (WEB)", "Alpine-3 (APP)", "cross-leaf"),
    ("Alpine-3 (APP)", "Alpine-1 (WEB)", "cross-leaf"),
    ("Alpine-1 (WEB)", "Alpine-5 (MGT)", "cross-leaf"),
    ("Alpine-2 (DB)",  "Alpine-3 (APP)", "cross-leaf"),
    ("Alpine-2 (DB)",  "Alpine-5 (MGT)", "cross-leaf"),
    ("Alpine-5 (MGT)", "Alpine-2 (DB)",  "cross-leaf"),
]


def alpine_ping(port, target_ip, count=4, timeout=2):
    """Ping từ Alpine host qua console (telnetlib), trả về (sent, received)."""
    import random
    sentinel = f"PING_DONE_{random.randint(10000,99999)}"

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

    def read_until_sentinel(marker, max_wait=30):
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
    max_ping_time = count * (timeout + 1) + 5
    tn.write(f"ping {target_ip} -c {count} -W {timeout}; echo {sentinel}\n".encode())
    # Skip the command echo line first
    time.sleep(0.5)
    r = read_until_sentinel(f"\n{sentinel}", max_wait=max_ping_time + 5)
    tn.get_socket().close()

    # Parse result
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
    print("=" * 65)
    print("  DC Fabric Connectivity Verification")
    print("=" * 65)
    print()

    passed = 0
    failed = 0
    errors = []

    for src_name, dst_name, test_type in TESTS:
        src = ALPINES[src_name]
        dst = ALPINES[dst_name]

        sent, recv = alpine_ping(src["port"], dst["ip"])

        if recv > 0:
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1
            errors.append(f"{src_name} -> {dst_name}")

        loss = f"{sent - recv}/{sent} lost" if sent > 0 else "no response"
        tag = f"[{test_type}]"
        print(f"  {status}  {src_name:20s} -> {dst_name:20s} {tag:14s} {loss}")

    # Summary
    print()
    print("-" * 65)
    total = passed + failed
    print(f"  Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed == 0:
        print("  Status: ALL TESTS PASSED - DC fabric fully functional!")
    else:
        print("  Status: SOME TESTS FAILED")
        print("  Failed paths:")
        for e in errors:
            print(f"    - {e}")
        print()
        print("  Troubleshooting:")
        print("    1. Run: python3 05-setup-all.py")
        print("    2. Check: ip route get <dst> from <src> iif <interface>")
        print("    3. Check: cat /proc/sys/net/ipv4/conf/*/forwarding")

    print("-" * 65)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
