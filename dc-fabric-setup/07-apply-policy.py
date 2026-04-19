#!/usr/bin/env python3
"""
07-apply-policy.py — Apply hoặc rollback Zero Trust iptables policy
====================================================================
Chạy từ: dis@gns3vm
Chức năng:
  - apply:    Áp dụng microsegmentation rules lên LEAF-1 + LEAF-2
  - rollback: Xóa tất cả rules, quay về ACCEPT all (debug/reset)
  - status:   Xem rules hiện tại trên cả 2 LEAF

Usage:
  python3 07-apply-policy.py apply      # Áp dụng Zero Trust policy
  python3 07-apply-policy.py rollback   # Xóa rules, mở hết traffic
  python3 07-apply-policy.py status     # Xem rules hiện tại
"""

import socket
import time
import sys

CONSOLE_HOST = "127.0.0.1"

NODES = {
    "LEAF-1": {"port": 5010, "user": "admin", "password": "YourPaSsWoRd"},
    "LEAF-2": {"port": 5015, "user": "admin", "password": "YourPaSsWoRd"},
}

# Subnet definitions
WEB = "10.1.100.0/24"
DB  = "10.1.200.0/24"
APP = "10.2.100.0/24"
MGT = "10.2.50.0/24"

# iptables rules — ĐỒNG BỘ trên cả 2 LEAF (defense in depth)
POLICY_RULES = [
    # Allow established connections (reply packets)
    "sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    # WEB → APP: allow
    f"sudo iptables -A FORWARD -s {WEB} -d {APP} -j ACCEPT",
    # APP → DB: allow
    f"sudo iptables -A FORWARD -s {APP} -d {DB} -j ACCEPT",
    # MGT → all: allow
    f"sudo iptables -A FORWARD -s {MGT} -j ACCEPT",
    # Default deny with logging
    'sudo iptables -A FORWARD -j LOG --log-prefix "[ZT-DENY] " --log-level 4',
    "sudo iptables -A FORWARD -j DROP",
]

ROLLBACK_RULES = [
    "sudo iptables -F FORWARD",
    "sudo iptables -P FORWARD ACCEPT",
]


def console_run(node_name, commands, read_output=False):
    """Connect to SONiC console and run commands."""
    cfg = NODES[node_name]
    s = socket.socket()
    try:
        s.connect((CONSOLE_HOST, cfg["port"]))
    except ConnectionRefusedError:
        print(f"  ERROR: {node_name} not reachable on port {cfg['port']}")
        return ""
    s.settimeout(2)

    def read_all(w=1):
        time.sleep(w)
        out = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                out += d
        except (socket.timeout, OSError):
            pass
        return out.decode(errors="ignore")

    # Login
    read_all(0.5)
    s.send(b"\n"); read_all(1)
    s.send(f"{cfg['user']}\n".encode()); read_all(1)
    s.send(f"{cfg['password']}\n".encode()); read_all(3)

    output = ""
    for cmd in commands:
        s.send((cmd + "\n").encode())
        r = read_all(2)
        if read_output:
            output += r

    s.close()
    return output


def apply_policy():
    """Apply Zero Trust iptables rules to both LEAFs."""
    print("=" * 60)
    print("  Applying Zero Trust Microsegmentation Policy")
    print("=" * 60)

    for name in ["LEAF-1", "LEAF-2"]:
        print(f"\n--- {name} ---")
        # Flush first, then apply
        commands = ["sudo iptables -F FORWARD"] + POLICY_RULES
        console_run(name, commands)
        # Show result
        output = console_run(name,
            ["sudo iptables -L FORWARD -n --line-numbers"],
            read_output=True)
        for line in output.split("\n"):
            line = line.strip()
            if line and "admin@sonic" not in line and "iptables" not in line:
                print(f"  {line}")

    print(f"\n{'='*60}")
    print("  Policy applied! Run: python3 08-verify-policy.py")
    print(f"{'='*60}")


def rollback_policy():
    """Remove all iptables rules, restore open forwarding."""
    print("=" * 60)
    print("  Rolling back — removing all FORWARD rules")
    print("=" * 60)

    for name in ["LEAF-1", "LEAF-2"]:
        print(f"  {name}: flushing FORWARD chain...")
        console_run(name, ROLLBACK_RULES)

    print("  Done. All traffic now flows freely (ACCEPT all).")


def show_status():
    """Show current iptables FORWARD rules on both LEAFs."""
    print("=" * 60)
    print("  Current FORWARD rules")
    print("=" * 60)

    for name in ["LEAF-1", "LEAF-2"]:
        print(f"\n--- {name} ---")
        output = console_run(name,
            ["sudo iptables -L FORWARD -n -v --line-numbers"],
            read_output=True)
        for line in output.split("\n"):
            line = line.strip()
            if line and "admin@sonic" not in line and "iptables" not in line:
                print(f"  {line}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 07-apply-policy.py [apply|rollback|status]")
        sys.exit(1)

    action = sys.argv[1].lower()
    if action == "apply":
        apply_policy()
    elif action == "rollback":
        rollback_policy()
    elif action == "status":
        show_status()
    else:
        print(f"Unknown action: {action}")
        print("Usage: python3 07-apply-policy.py [apply|rollback|status]")
        sys.exit(1)
