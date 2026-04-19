#!/usr/bin/env python3
"""
10-suricata-analyze.py — Chạy Suricata phân tích và parse alerts
================================================================
Chạy từ: dis@gns3vm (host, nơi Suricata đã được cài)
Chức năng:
  1. Chạy Suricata đọc pcap từ GNS3 captures (offline mode)
  2. Hoặc listen live trên IDS node bridge interface
  3. Parse eve.json → báo cáo alerts theo Zero Trust policy

Mode:
    python3 10-suricata-analyze.py --pcap <file.pcap>   # Offline: đọc pcap
    python3 10-suricata-analyze.py --live <iface>        # Live: sniff interface
    python3 10-suricata-analyze.py --parse               # Chỉ parse eve.json hiện có
"""

import subprocess
import json
import sys
import os
import time
import argparse
from datetime import datetime
from collections import defaultdict

# =============================================================================
# CONFIG
# =============================================================================
SURICATA_CONFIG = "/3s-com/zma/suricata/suricata-zt.yaml"
EVE_LOG = "/3s-com/zma/suricata/logs/eve.json"
FAST_LOG = "/3s-com/zma/suricata/logs/fast.log"
LOG_DIR  = "/3s-com/zma/suricata/logs/"

# Zero Trust zones (để hiển thị tên đẹp)
ZONE_MAP = {
    "10.1.100": "WEB",
    "10.1.200": "DB",
    "10.2.100": "APP",
    "10.2.50":  "MGT",
}

# SID → mô tả ngắn
SID_NAMES = {
    9000001: "WEB→DB bypass (critical)",
    9000002: "DB outbound (critical)",
    9000003: "APP→WEB lateral movement",
    9000004: "WEB→MGT unauthorized",
    9000005: "APP→MGT unauthorized",
    9000010: "ICMP ping sweep",
    9000011: "Port scan",
    9000020: "MGT zone audit",
}

PRIORITY_LABELS = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW/AUDIT"}


def zone_of(ip):
    for prefix, zone in ZONE_MAP.items():
        if ip.startswith(prefix):
            return zone
    return ip


# =============================================================================
# Suricata runner
# =============================================================================

def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def clear_old_logs():
    """Xóa logs cũ trước khi chạy mới."""
    for f in [EVE_LOG, FAST_LOG]:
        if os.path.exists(f):
            os.remove(f)
            print(f"  [~] Cleared: {f}")


def run_suricata_pcap(pcap_file):
    """Chạy Suricata đọc file pcap (offline)."""
    if not os.path.exists(pcap_file):
        print(f"  [!] PCAP file không tồn tại: {pcap_file}")
        return False

    print(f"\n[*] Chạy Suricata offline: {pcap_file}")
    print(f"    Config: {SURICATA_CONFIG}")
    print(f"    Output: {LOG_DIR}")

    cmd = [
        "suricata",
        "-c", SURICATA_CONFIG,
        "-r", pcap_file,
        "--runmode", "single",
        "-l", LOG_DIR,
    ]

    print(f"    CMD: {' '.join(cmd)}\n")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0 and result.returncode != 1:
            print(f"  [!] Suricata exit code: {result.returncode}")
            if result.stderr:
                for line in result.stderr.strip().split("\n")[-5:]:
                    print(f"      {line}")
        return True
    except FileNotFoundError:
        print("  [!] Suricata không được cài: apt-get install suricata / apk add suricata")
        return False
    except subprocess.TimeoutExpired:
        print("  [!] Suricata timeout (120s)")
        return False


def run_suricata_live(interface, duration=30):
    """Chạy Suricata live sniff trên interface (chạy background)."""
    print(f"\n[*] Chạy Suricata live trên {interface} ({duration}s)...")
    cmd = [
        "suricata",
        "-c", SURICATA_CONFIG,
        "-i", interface,
        "-l", LOG_DIR,
    ]
    print(f"    CMD: {' '.join(cmd)}")
    print(f"    Chờ {duration}s để capture traffic...")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        return True
    except FileNotFoundError:
        print("  [!] Suricata không được cài")
        return False


# =============================================================================
# Alert parser
# =============================================================================

def parse_eve_json():
    """Đọc eve.json và trả về danh sách alerts."""
    if not os.path.exists(EVE_LOG):
        return []

    alerts = []
    with open(EVE_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def print_report(alerts):
    """In báo cáo chi tiết alerts."""
    print("\n" + "=" * 70)
    print("  Suricata IDS — Zero Trust Alert Report")
    print("=" * 70)

    if not alerts:
        print("\n  Không có alerts nào được phát hiện.")
        print("  → Kiểm tra: traffic có chạy qua Hub không? Suricata đọc đúng pcap?")
        return

    # Group by SID
    by_sid = defaultdict(list)
    for a in alerts:
        sid = a.get("alert", {}).get("signature_id", 0)
        by_sid[sid].append(a)

    # Summary table
    print(f"\n  {'SID':<10} {'Count':>5}  {'Priority':<10}  Description")
    print(f"  {'-'*9}  {'-'*5}  {'-'*10}  {'-'*35}")

    total_critical = 0
    total_high = 0
    for sid in sorted(by_sid.keys()):
        events = by_sid[sid]
        count = len(events)
        prio = events[0].get("alert", {}).get("severity", 3)
        prio_label = PRIORITY_LABELS.get(prio, f"P{prio}")
        desc = SID_NAMES.get(sid, events[0].get("alert", {}).get("signature", "?"))
        print(f"  {sid:<10} {count:>5}  {prio_label:<10}  {desc}")
        if prio == 1:
            total_critical += count
        elif prio == 2:
            total_high += count

    # Detail per alert (chỉ show critical + high để không spam)
    print(f"\n  {'─'*70}")
    print(f"  Alerts chi tiết (Critical + High only):")
    print(f"  {'─'*70}")

    shown = 0
    max_show = 20
    for a in sorted(alerts, key=lambda x: x.get("alert", {}).get("severity", 9)):
        prio = a.get("alert", {}).get("severity", 9)
        if prio > 2:
            continue
        if shown >= max_show:
            remaining = sum(1 for x in alerts
                           if x.get("alert", {}).get("severity", 9) <= 2) - shown
            if remaining > 0:
                print(f"  ... và {remaining} alerts khác")
            break

        ts    = a.get("timestamp", "")[:19].replace("T", " ")
        src   = a.get("src_ip", "?")
        dst   = a.get("dest_ip", "?")
        sport = a.get("src_port", "")
        dport = a.get("dest_port", "")
        msg   = a.get("alert", {}).get("signature", "?")
        src_z = zone_of(src)
        dst_z = zone_of(dst)

        sport_s = f":{sport}" if sport else ""
        dport_s = f":{dport}" if dport else ""
        print(f"\n  [{ts}] {msg}")
        print(f"    {src}{sport_s} ({src_z}) → {dst}{dport_s} ({dst_z})")
        shown += 1

    # Final summary
    print(f"\n  {'='*70}")
    print(f"  SUMMARY: {len(alerts)} alerts total")
    print(f"    Critical (P1): {total_critical}")
    print(f"    High (P2):     {total_high}")
    print(f"    Other:         {len(alerts) - total_critical - total_high}")

    if total_critical > 0:
        print(f"\n  *** ZERO TRUST VIOLATIONS DETECTED ***")
        print(f"  Suricata đã phát hiện {total_critical} critical policy violations.")
        print(f"  Đây là bằng chứng IDS hoạt động trong datacenter architecture.")
    else:
        print(f"\n  Không có critical violations — policy đang được enforce tốt.")

    print(f"  {'='*70}\n")


def list_gns3_captures():
    """Tìm pcap files trong GNS3 project captures."""
    search_dirs = [
        "/opt/gns3/projects",
        "/home/dis/GNS3/projects",
        f"/tmp/gns3",
    ]
    pcaps = []
    for d in search_dirs:
        if os.path.exists(d):
            for root, dirs, files in os.walk(d):
                for f in files:
                    if f.endswith(".pcap") or f.endswith(".pcapng"):
                        pcaps.append(os.path.join(root, f))
    return pcaps


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Chạy Suricata phân tích traffic Zero Trust lab"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--pcap",  metavar="FILE",
                     help="Phân tích file pcap (offline mode)")
    grp.add_argument("--live",  metavar="IFACE",
                     help="Sniff trực tiếp interface (live mode)")
    grp.add_argument("--parse", action="store_true",
                     help="Chỉ parse eve.json hiện có (không chạy Suricata)")
    grp.add_argument("--list-captures", action="store_true",
                     help="Liệt kê pcap files của GNS3")
    parser.add_argument("--duration", type=int, default=30,
                        help="Thời gian sniff live mode (giây, default=30)")
    args = parser.parse_args()

    ensure_log_dir()

    if args.list_captures:
        print("GNS3 capture files:")
        pcaps = list_gns3_captures()
        if pcaps:
            for p in sorted(pcaps):
                size = os.path.getsize(p)
                print(f"  {p}  ({size:,} bytes)")
        else:
            print("  Không tìm thấy pcap files")
            print("  Hint: Dùng GNS3 GUI → right-click link → Start capture")
        return 0

    elif args.parse:
        print(f"[*] Parse eve.json: {EVE_LOG}")
        alerts = parse_eve_json()
        print(f"[*] Found {len(alerts)} alerts")
        print_report(alerts)

    elif args.pcap:
        clear_old_logs()
        ok = run_suricata_pcap(args.pcap)
        if ok:
            time.sleep(1)  # Flush writes
            alerts = parse_eve_json()
            print(f"[*] Found {len(alerts)} alerts")
            print_report(alerts)

    elif args.live:
        clear_old_logs()
        ok = run_suricata_live(args.live, args.duration)
        if ok:
            time.sleep(1)
            alerts = parse_eve_json()
            print(f"[*] Found {len(alerts)} alerts")
            print_report(alerts)

    else:
        # Default: không có args → hướng dẫn
        print("Cách dùng:")
        print("  python3 10-suricata-analyze.py --pcap <file.pcap>")
        print("  python3 10-suricata-analyze.py --live eth0 --duration 60")
        print("  python3 10-suricata-analyze.py --parse")
        print("  python3 10-suricata-analyze.py --list-captures")
        print()
        print(f"Logs dir: {LOG_DIR}")
        print(f"Config:   {SURICATA_CONFIG}")
        print(f"Rules:    /3s-com/zma/suricata/rules/zt-lab.rules")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
