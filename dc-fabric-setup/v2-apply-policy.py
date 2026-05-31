#!/usr/bin/env python3
"""V2 8x8 microsegmentation policy → iptables rules per LEAF.

Reads policy matrix from DATAPLANE_V2.md §6.1. For each LEAF, generates
iptables FORWARD rules covering flows where source OR destination is a
local zone (defense-in-depth: both source-leaf and dest-leaf enforce).
Push via GNS3 console (telnet) — no SSH.
"""
import pexpect, time, sys

ZONES = {
    "WEB":          ("10.1.100.0/24", "LEAF-1"),
    "DB-OLTP":      ("10.1.200.0/24", "LEAF-1"),
    "APP-CORE":     ("10.2.100.0/24", "LEAF-2"),
    "MGT":          ("10.2.50.0/24",  "LEAF-2"),
    "APP-GW":       ("10.3.100.0/24", "LEAF-3"),
    "DB-ANALYTICS": ("10.3.200.0/24", "LEAF-3"),
    "WORKER":       ("10.4.100.0/24", "LEAF-4"),
    "MONITORING":   ("10.4.200.0/24", "LEAF-4"),
}

# Matrix: True = ALLOW, False = DENY. src → dst.
MATRIX = {
    "WEB":          {"APP-GW": True},
    "APP-GW":       {"APP-CORE": True},
    "APP-CORE":     {"WORKER": True, "DB-OLTP": True, "DB-ANALYTICS": True},
    "WORKER":       {"DB-OLTP": True},
    "DB-OLTP":      {"DB-ANALYTICS": True},
    "DB-ANALYTICS": {},          # sink, no outbound
    "MONITORING":   {z: True for z in ZONES if z != "MGT" and z != "MONITORING"},
    "MGT":          {z: True for z in ZONES if z != "MGT"},
}

LEAF_CONSOLE = {"LEAF-1": 5010, "LEAF-2": 5015, "LEAF-3": 5025, "LEAF-4": 5027}


def gen_rules_for_leaf(leaf_name):
    """Generate iptables rules touching this leaf's local zones."""
    local_zones = [z for z,(_,l) in ZONES.items() if l == leaf_name]
    rules = [
        "iptables -P FORWARD DROP",
        "iptables -F FORWARD",
        "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    # Add ACCEPT for every allowed flow touching a local zone (src or dst)
    for src, dst_map in MATRIX.items():
        for dst, allowed in dst_map.items():
            if not allowed: continue
            if src not in local_zones and dst not in local_zones:
                continue   # this leaf doesn't touch this flow
            src_cidr = ZONES[src][0]
            dst_cidr = ZONES[dst][0]
            rules.append(f"iptables -A FORWARD -s {src_cidr} -d {dst_cidr} -j ACCEPT")
    rules.append("iptables -A FORWARD -j DROP")
    return rules


def login(port):
    P = "RDY""X> "
    c = pexpect.spawn(f"telnet 127.0.0.1 {port}", timeout=60, encoding="utf-8")
    c.send("\r"); time.sleep(1); c.send("\r"); time.sleep(1)
    i = c.expect([r"login:", r"\$ ", pexpect.TIMEOUT], timeout=30)
    if i == 0:
        c.sendline("admin"); c.expect(r"[Pp]assword:", timeout=10)
        c.sendline("YourPaSsWoRd"); c.expect(r"\$ ", timeout=20)
    c.sendline("PS1='RDY''X> '"); c.expect(P, timeout=12)
    return c, P


def apply_leaf(leaf, port):
    print(f"\n========== {leaf} (console :{port}) ==========")
    rules = gen_rules_for_leaf(leaf)
    print(f"  generated {len(rules)} rules")
    c, P = login(port)
    for r in rules:
        c.sendline(f"sudo {r}")
        c.expect(P, timeout=10)
    # Verify
    c.sendline("sudo iptables -L FORWARD -n | head -20")
    c.expect(P, timeout=10)
    print("  --- iptables FORWARD ---")
    for ln in c.before.split("\n")[1:]:
        if "ACCEPT" in ln or "DROP" in ln or "policy" in ln:
            print(f"    {ln.strip()[:100]}")
    c.sendline("exit"); time.sleep(0.3)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in LEAF_CONSOLE:
        apply_leaf(sys.argv[1], LEAF_CONSOLE[sys.argv[1]])
    else:
        for leaf, port in LEAF_CONSOLE.items():
            apply_leaf(leaf, port)
        print("\n=== 8x8 policy applied to all 4 LEAVES ===")
