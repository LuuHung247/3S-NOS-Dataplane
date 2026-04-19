#!/usr/bin/env python3
"""GNS3 Canvas Inspector - xem topology nhanh"""

import urllib.request
import json
import sys

GNS3_URL = "http://localhost:3080/v2"
PROJECT_NAME = "micro-segmentation-lab"

def api(path):
    with urllib.request.urlopen(f"{GNS3_URL}{path}") as r:
        return json.load(r)

def main():
    # Tìm project
    projects = api("/projects")
    project = next((p for p in projects if p["name"] == PROJECT_NAME), None)
    if not project:
        print(f"Không tìm thấy project: {PROJECT_NAME}")
        sys.exit(1)
    pid = project["project_id"]

    # Nodes
    nodes = api(f"/projects/{pid}/nodes")
    node_map = {n["node_id"]: n["name"] for n in nodes}

    # Lay console ports de tinh SSH/telnet info
    # SONiC: SSH admin@<nat-ip> (can biet IP tu DHCP)
    # Alpine: telnet truc tiep vao console port
    nat_ip = "112.137.129.232"

    print(f"=== PROJECT: {PROJECT_NAME} ===\n")
    print(f"{'NODES':<25} {'STATUS':<10} {'CONSOLE':<35} {'SSH'}")
    print("-" * 90)
    for n in nodes:
        icon = "+" if n["status"] == "started" else "-"
        console_port = n.get("console")
        node_type = n["node_type"]
        name = n["name"]

        console_str = f"telnet {nat_ip}:{console_port}" if console_port else "N/A"

        if node_type == "nat":
            ssh_str = "(NAT node)"
        elif "SONIC" in name.upper():
            ssh_str = f"ssh admin@<dhcp-ip>  (pw: YourPaSsWoRd)"
        else:
            ssh_str = "login: root (no pw)"

        print(f"  [{icon}] {name:<22} {n['status']:<10} {console_str:<35} {ssh_str}")

    # Links
    links = api(f"/projects/{pid}/links")
    print(f"\nLINKS:")
    if not links:
        print("  (chua co link nao)")
    for l in links:
        ns = l["nodes"]
        if len(ns) >= 2:
            a = node_map.get(ns[0]["node_id"], ns[0]["node_id"][:8])
            b = node_map.get(ns[1]["node_id"], ns[1]["node_id"][:8])
            pa = ns[0]["adapter_number"]
            pb = ns[1]["adapter_number"]
            def eth(adapter, node_name):
                if "SONIC" in node_name.upper():
                    return f"Ethernet{adapter*4}"
                return f"eth{adapter}"
            print(f"  {a}({eth(pa,a)}) <--> {b}({eth(pb,b)})")

    print()

if __name__ == "__main__":
    main()
