#!/usr/bin/env python3
"""
11-ids-demo.py — Demo: Generate Zero Trust violations + Suricata detection
==========================================================================
Chạy từ: dis@gns3vm
Chức năng: Demo cho thesis — tạo các policy violations từ Alpine nodes,
           sau đó chạy Suricata (hoặc parse eve.json) và báo cáo kết quả.

Demo flow:
  1. Generate violations (ping từ các zones vi phạm Zero Trust policy)
  2. Chạy Suricata hoặc parse eve.json
  3. Print báo cáo: violations detected vs expected

Usage:
    python3 11-ids-demo.py              # Full demo (generate + detect)
    python3 11-ids-demo.py --generate   # Chỉ generate violations (không analyze)
    python3 11-ids-demo.py --detect     # Chỉ detect (parse eve.json hiện có)
"""

import telnetlib
import time
import sys
import os
import json
import random
import subprocess
import argparse
from collections import defaultdict

# =============================================================================
# CONFIG
# =============================================================================
CONSOLE_HOST = "127.0.0.1"

# Alpine console ports + IPs (theo README)
ALPINES = {
    "WEB": {"port": 5008, "ip": "10.1.100.10", "zone": "WEB"},
    "DB":  {"port": 5011, "ip": "10.1.200.10", "zone": "DB"},
    "APP": {"port": 5014, "ip": "10.2.100.10", "zone": "APP"},
    "MGT": {"port": 5016, "ip": "10.2.50.10",  "zone": "MGT"},
}

# Violations cần generate: (src, dst, mô tả, SID expected)
VIOLATIONS = [
    ("WEB", "DB",  "WEB direct to DB — microsegmentation bypass",  9000001),
    ("APP", "WEB", "APP reverse call to WEB — lateral movement",    9000003),
    ("WEB", "MGT", "WEB to MGT — unauthorized access attempt",      9000004),
    ("APP", "MGT", "APP to MGT — unauthorized access",              9000005),
]

# Legitimate traffic (để contrast trong demo)
LEGIT_TRAFFIC = [
    ("WEB", "APP", "WEB → APP (legitimate API call)", None),
    ("APP", "DB",  "APP → DB (legitimate DB query)",  None),
]

EVE_LOG = "/3s-com/zma/suricata/logs/eve.json"
SURICATA_CONFIG = "/3s-com/zma/suricata/suricata-zt.yaml"
LOG_DIR = "/3s-com/zma/suricata/logs/"

SID_NAMES = {
    9000001: "[ZT-VIOLATION] WEB direct to DB",
    9000002: "[ZT-VIOLATION] DB initiating outbound",
    9000003: "[ZT-ALERT] APP reverse call to WEB",
    9000004: "[ZT-ALERT] WEB to MGT",
    9000005: "[ZT-ALERT] APP to MGT",
    9000010: "[ZT-INFO] ICMP ping sweep",
    9000011: "[ZT-INFO] Port scan",
    9000020: "[ZT-AUDIT] Management zone access",
}


# =============================================================================
# Console helpers (giống 08-verify-policy.py)
# =============================================================================

def alpine_ping(port, target_ip, count=3, timeout=2):
    """Ping từ Alpine host qua telnet console. Return (sent, received)."""
    sentinel = f"DONE_{random.randint(10000, 99999)}"

    try:
        tn = telnetlib.Telnet(CONSOLE_HOST, port, timeout=5)
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

    tn.write(b"\x03")
    drain(0.5)
    tn.write(b"\n")
    r = drain(1.0)
    if "login:" in r:
        tn.write(b"root\n")
        drain(2.0)
    tn.write(b"\n")
    drain(0.5)

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


# =============================================================================
# Step 1: Generate violations
# =============================================================================

def generate_violations():
    print("=" * 70)
    print("  [DEMO] Step 1: Generate Zero Trust Policy Violations")
    print("=" * 70)
    print()
    print("  Generating legitimate traffic (baseline)...")
    print(f"  {'Source':5s} → {'Dest':5s}  {'Type':<40}  Result")
    print(f"  {'-'*5}   {'-'*5}  {'-'*40}  {'-'*10}")

    for src_name, dst_name, desc, _ in LEGIT_TRAFFIC:
        src = ALPINES[src_name]
        dst = ALPINES[dst_name]
        sent, recv = alpine_ping(src["port"], dst["ip"])
        result = f"{recv}/{sent} recv" if sent > 0 else "UNREACHABLE"
        print(f"  {src_name:5s} → {dst_name:5s}  {desc:<40}  {result}")

    print()
    print("  Generating VIOLATIONS (should be blocked by iptables, visible to IDS)...")
    print(f"  {'Source':5s} → {'Dest':5s}  {'Type':<40}  Expected  Actual")
    print(f"  {'-'*5}   {'-'*5}  {'-'*40}  {'-'*8}  {'-'*10}")

    results = []
    for src_name, dst_name, desc, sid in VIOLATIONS:
        src = ALPINES[src_name]
        dst = ALPINES[dst_name]
        sent, recv = alpine_ping(src["port"], dst["ip"])

        # Violations đều bị iptables block (DENY) — nhưng traffic vẫn chạy qua Hub
        # → Suricata thấy packets trước khi iptables drop
        expected_block = "DENY"
        actual = "ALLOW" if recv > 0 else "DENY"
        policy_ok = actual == expected_block

        results.append({
            "src": src_name, "dst": dst_name,
            "desc": desc, "sid": sid,
            "sent": sent, "recv": recv,
            "policy_ok": policy_ok
        })

        status = "BLOCKED-by-iptables" if policy_ok else f"LEAK! {recv}/{sent} recv"
        print(f"  {src_name:5s} → {dst_name:5s}  {desc:<40}  {expected_block:8s}  {status}")

    all_blocked = all(r["policy_ok"] for r in results)
    print()
    if all_blocked:
        print("  [OK] Tất cả violations bị iptables BLOCK — Zero Trust đang hoạt động.")
        print("  [*]  Traffic vẫn đi qua Hub → IDS thấy packets trước khi drop.")
    else:
        print("  [!]  Một số violations KHÔNG bị block — kiểm tra iptables policy!")
        print("       Chạy: python3 07-apply-policy.py apply")
    print()
    return results


# =============================================================================
# Step 2: Detect với Suricata
# =============================================================================

def find_pcap_for_hub():
    """Tìm pcap file của Hub captures nếu có."""
    search_dirs = ["/opt/gns3/projects", "/tmp"]
    for d in search_dirs:
        if not os.path.exists(d):
            continue
        for root, dirs, files in os.walk(d):
            for f in files:
                if (f.endswith(".pcap") or f.endswith(".pcapng")) and "hub" in f.lower():
                    return os.path.join(root, f)
    return None


def run_suricata_if_available(pcap_file=None):
    """Chạy Suricata nếu có pcap, hoặc parse eve.json existing."""
    os.makedirs(LOG_DIR, exist_ok=True)

    if pcap_file and os.path.exists(pcap_file):
        print(f"  [*] Chạy Suricata với pcap: {pcap_file}")
        cmd = ["suricata", "-c", SURICATA_CONFIG, "-r", pcap_file,
               "--runmode", "single", "-l", LOG_DIR]
        try:
            subprocess.run(cmd, capture_output=True, timeout=60)
            time.sleep(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return parse_eve()


def parse_eve():
    """Parse eve.json và trả về alerts."""
    if not os.path.exists(EVE_LOG):
        return []
    alerts = []
    with open(EVE_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "alert":
                alerts.append(ev)
    return alerts


# =============================================================================
# Step 3: Print demo report
# =============================================================================

def print_demo_report(violations_generated, alerts):
    print("=" * 70)
    print("  [DEMO] Step 2: Suricata IDS Detection Results")
    print("=" * 70)
    print()

    if not alerts:
        print("  Không tìm thấy alerts trong eve.json.")
        print()
        print("  Lý do có thể:")
        print("    1. Hub captures chưa được start trong GNS3 GUI")
        print("       → GNS3 GUI → right-click link Hub↔SPINE → Start capture")
        print("    2. Suricata chưa phân tích pcap đó")
        print("       → python3 10-suricata-analyze.py --list-captures")
        print("       → python3 10-suricata-analyze.py --pcap <file>")
        print("    3. IDS node promisc mode chưa được config")
        print("       → Chạy lại: python3 09-deploy-ids.py --status")
        print()
        print("  Demo vẫn thành công về mặt policy enforcement (iptables block)")
        print("  Suricata detection cần pcap từ Hub links để analyze.")
        return

    # Group alerts by SID
    by_sid = defaultdict(int)
    for a in alerts:
        sid = a.get("alert", {}).get("signature_id", 0)
        by_sid[sid] += 1

    # Detect rate
    expected_sids = {v["sid"] for v in violations_generated if v["sid"]}
    detected_sids = set(by_sid.keys())
    detected_violations = expected_sids & detected_sids
    missed_violations = expected_sids - detected_sids

    print(f"  {'Violation':<45}  {'Expected SID':<12}  {'Detected':>8}  Status")
    print(f"  {'-'*44}  {'-'*12}  {'-'*8}  {'-'*10}")

    for v in violations_generated:
        sid = v["sid"]
        count = by_sid.get(sid, 0)
        status = f"YES ({count}x)" if count > 0 else "NOT SEEN"
        ok = "DETECTED" if count > 0 else "MISSED"
        print(f"  {v['desc']:<45}  {sid:<12}  {count:>8}  {ok}")

    print()
    print(f"  Detection rate: {len(detected_violations)}/{len(expected_sids)} violations detected")

    # Bonus alerts (recon, audit)
    bonus_sids = detected_sids - expected_sids
    if bonus_sids:
        print(f"\n  Bonus detections (không phải violations trực tiếp):")
        for sid in sorted(bonus_sids):
            name = SID_NAMES.get(sid, f"SID {sid}")
            print(f"    [{by_sid[sid]}x] {name}")

    # Final verdict
    print()
    print("=" * 70)
    if len(detected_violations) == len(expected_sids):
        print("  RESULT: Suricata phát hiện 100% Zero Trust violations!")
        print()
        print("  Thesis demonstration points:")
        print("    1. iptables BLOCKS violations → Zero Trust policy enforced")
        print("    2. Hub TAP mirrors ALL traffic → IDS sees packets before drop")
        print("    3. Suricata alerts match EXACTLY the defined policy violations")
        print("    4. Out-of-band IDS (NIST 800-207) — không ảnh hưởng traffic path")
        print("    5. eve.json provides structured audit trail for SIEM integration")
    elif len(detected_violations) > 0:
        missed = list(missed_violations)
        print(f"  RESULT: Phát hiện {len(detected_violations)}/{len(expected_sids)} violations.")
        print(f"  Missed: {missed}")
        print("  → Kiểm tra Hub captures và Suricata rules.")
    else:
        print("  RESULT: Suricata không phát hiện violations.")
        print("  → Cần chạy Suricata với pcap từ Hub links.")
    print("=" * 70)
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Demo Zero Trust violations + Suricata detection"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--generate", action="store_true",
                     help="Chỉ generate violations, không analyze")
    grp.add_argument("--detect",   action="store_true",
                     help="Chỉ parse eve.json và báo cáo")
    parser.add_argument("--pcap", metavar="FILE",
                        help="Dùng pcap file này cho Suricata (override auto-detect)")
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║     Zero Trust Microsegmentation — Suricata IDS Demo               ║")
    print("║     GNS3 SONiC Spine-Leaf Lab                                       ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()

    if args.generate:
        generate_violations()
        print("  [*] Violations generated. Bước tiếp:")
        print("      python3 10-suricata-analyze.py --pcap <hub-capture.pcap>")
        print("      python3 11-ids-demo.py --detect")
        return 0

    if args.detect:
        alerts = parse_eve()
        print(f"  [*] Parsing eve.json: {len(alerts)} alerts found")
        # Create placeholder violations list cho report
        violations = [{"src": s, "dst": d, "desc": desc, "sid": sid,
                       "sent": 0, "recv": 0, "policy_ok": True}
                      for s, d, desc, sid in VIOLATIONS]
        print_demo_report(violations, alerts)
        return 0

    # Full demo: generate + detect
    print("  Mode: Full demo (generate violations + detect)\n")

    # Step 1: Generate
    violation_results = generate_violations()

    # Step 2: Detect
    print("=" * 70)
    print("  [DEMO] Phân tích với Suricata IDS")
    print("=" * 70)
    print()

    pcap_file = args.pcap
    if not pcap_file:
        pcap_file = find_pcap_for_hub()
        if pcap_file:
            print(f"  [*] Auto-found pcap: {pcap_file}")
        else:
            print("  [*] Không tìm thấy Hub pcap — dùng eve.json hiện có (nếu có).")
            print("  [*] Hint: Trong GNS3 GUI → right-click link SPINE↔Hub → Start capture")
            print("            Sau đó chạy: python3 10-suricata-analyze.py --list-captures")
            print()

    alerts = run_suricata_if_available(pcap_file)

    # Step 3: Report
    print_demo_report(violation_results, alerts)

    return 0


if __name__ == "__main__":
    sys.exit(main())
