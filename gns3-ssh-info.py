#!/usr/bin/env python3
"""
GNS3 SSH Info - Tu dong lay IP cua tung node qua telnet console
Usage: python3 gns3-ssh-info.py
"""

import urllib.request
import subprocess
import json
import sys
import re

GNS3_URL = "http://localhost:3080/v2"
PROJECT  = "micro-segmentation-lab"
NAT_IP   = "112.137.129.232"

def api(path):
    with urllib.request.urlopen(f"{GNS3_URL}{path}") as r:
        return json.load(r)

def get_arp_table():
    """Doc ARP table, tra ve dict mac -> ip"""
    mac_to_ip = {}
    try:
        out = subprocess.check_output(["arp", "-n"], text=True)
        for line in out.splitlines():
            parts = line.split()
            # Format: IP  HWtype  MAC  Flags  Iface
            if len(parts) >= 3 and re.match(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", parts[2]):
                ip  = parts[0]
                mac = parts[2].lower()
                mac_to_ip[mac] = ip
    except Exception:
        pass
    return mac_to_ip

def main():
    projects = api("/projects")
    project  = next((p for p in projects if p["name"] == PROJECT), None)
    if not project:
        print(f"Khong tim thay project: {PROJECT}")
        sys.exit(1)
    pid = project["project_id"]

    nodes    = api(f"/projects/{pid}/nodes")
    arp      = get_arp_table()

    print(f"=== GNS3 SSH Info - {PROJECT} ===\n")
    print(f"  {'NODE':<22} {'STATUS':<10} {'IP':<18} {'SSH COMMAND'}")
    print("  " + "-" * 80)

    for n in nodes:
        name   = n["name"]
        status = n.get("status", n.get("node_status", "unknown"))
        ntype  = n["node_type"]
        port   = n.get("console")
        icon   = "+" if status == "started" else "-"

        if ntype == "nat":
            print(f"  [{icon}] {name:<22} {status:<10} {'(NAT)':<18}")
            continue

        # Lay MAC cua adapter 0 (eth0 - interface noi NAT)
        ports = n.get("ports", [])
        mac   = next((p.get("mac_address", "").lower()
                      for p in ports if p.get("adapter_number") == 0), "")

        ip = arp.get(mac)

        if ip:
            if "SONIC" in name.upper():
                ssh_cmd = f"ssh admin@{ip}"
            else:
                ssh_cmd = f"ssh root@{ip}"
            print(f"  [{icon}] {name:<22} {status:<10} {ip:<18} {ssh_cmd}")
        else:
            note = "no DHCP / not started" if status != "started" else "no IP (DHCP not configured)"
            print(f"  [{icon}] {name:<22} {status:<10} {'---':<18} telnet {NAT_IP}:{port}  ({note})")

    print()

if __name__ == "__main__":
    main()
