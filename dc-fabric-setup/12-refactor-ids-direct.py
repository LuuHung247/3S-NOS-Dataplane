#!/usr/bin/env python3
"""
12-refactor-ids-direct.py — Refactor IDS: Hub → Direct LEAF↔IDS + tc mirred
=============================================================================
Chạy từ: dis@gns3vm

Thay đổi:
  TRƯỚC: SPINE ↔ Hub ↔ LEAF  (IDS gắn vào Hub)
  SAU:   SPINE ↔ LEAF trực tiếp
         LEAF-1(eth4) ↔ IDS(eth0)   ← tc mirred mirror Vlan ingress
         LEAF-2(eth4) ↔ IDS(eth1)   ← tc mirred mirror Vlan ingress

Tại sao tốt hơn Hub:
  - tc mirred chạy trước iptables → IDS thấy violations
  - Không cần Hub node thừa
  - Giống Everflow (SONiC hardware) nhất có thể trên VS
"""

import urllib.request
import urllib.error
import json
import sys
import time
import telnetlib

# =============================================================================
# CONFIG
# =============================================================================
GNS3_URL   = "http://localhost:3080/v2"
PROJECT_ID = "b6bf1cd6-8d58-41d4-941c-893020abd2a3"

SPINE_ID  = "7364a9ca-a155-4328-832d-fa3b818dd2e9"
LEAF1_ID  = "b49505fd-4f50-4659-bf39-9d548190663f"
LEAF2_ID  = "c62b0bdd-3bd2-4b84-a531-36450236378e"

CONSOLE_HOST = "127.0.0.1"
LEAF1_CONSOLE = 5010
LEAF2_CONSOLE = 5015

# Vlan interfaces trên mỗi LEAF cần mirror
LEAF1_VLANS = ["Vlan100", "Vlan200"]   # WEB zone, DB zone
LEAF2_VLANS = ["Vlan100", "Vlan300"]   # APP zone, MGT zone

# =============================================================================
# API helpers
# =============================================================================

def api(method, path, data=None):
    url = f"{GNS3_URL}{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"Content-Type": "application/json"} if body else {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            try:
                return json.load(r)
            except Exception:
                return {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RuntimeError(f"{method} {path} → {e.code}: {e.read().decode()}") from e


def get_nodes():
    return api("GET", f"/projects/{PROJECT_ID}/nodes")


def get_links():
    return api("GET", f"/projects/{PROJECT_ID}/links")


def find_node(name):
    for n in get_nodes():
        if n["name"] == name:
            return n
    return None


def create_link(node_a, adap_a, port_a, node_b, adap_b, port_b, label=""):
    link = api("POST", f"/projects/{PROJECT_ID}/links", {
        "nodes": [
            {"node_id": node_a, "adapter_number": adap_a, "port_number": port_a},
            {"node_id": node_b, "adapter_number": adap_b, "port_number": port_b},
        ]
    })
    print(f"  [+] Link {label}: {link['link_id'][:8]}...")
    return link["link_id"]


def delete_link(link_id, label=""):
    result = api("DELETE", f"/projects/{PROJECT_ID}/links/{link_id}")
    if result is None:
        print(f"  [-] Link {label} không còn (skip)")
    else:
        print(f"  [-] Xóa link {label} OK")


def delete_node(node_id, name):
    result = api("DELETE", f"/projects/{PROJECT_ID}/nodes/{node_id}")
    if result is None:
        print(f"  [-] Node {name} không còn (skip)")
    else:
        print(f"  [-] Xóa node {name} OK")


def stop_node(node_id, name):
    try:
        api("POST", f"/projects/{PROJECT_ID}/nodes/{node_id}/stop")
        print(f"  [>] Stop {name} OK")
    except Exception:
        pass


def start_node(node_id, name):
    api("POST", f"/projects/{PROJECT_ID}/nodes/{node_id}/start")
    print(f"  [>] Start {name} OK")


# =============================================================================
# Telnet helpers
# =============================================================================

def run_cmds_on_sonic(console_port, node_name, cmds):
    """Chạy commands trên SONiC node qua telnet."""
    print(f"\n  [telnet] {node_name} (port {console_port})...")
    try:
        tn = telnetlib.Telnet(CONSOLE_HOST, console_port, timeout=10)
    except Exception as e:
        print(f"  [!] Không kết nối được: {e}")
        return

    def drain(wait=0.5):
        time.sleep(wait)
        try:
            return tn.read_very_eager().decode(errors="ignore")
        except EOFError:
            return ""

    # Login
    tn.write(b"\n")
    r = drain(1.5)
    if "login:" in r:
        tn.write(b"admin\n")
        drain(1.0)
        tn.write(b"YourPaSsWoRd\n")
        drain(2.0)
    tn.write(b"\n")
    drain(0.5)

    for cmd in cmds:
        print(f"    > {cmd[:70]}")
        tn.write(f"{cmd}\n".encode())
        time.sleep(0.8)
        out = drain(0.3)
        # Print output lines nếu có lỗi
        for line in out.split("\n"):
            line = line.strip()
            if line and any(k in line.lower() for k in ["error", "cannot", "failed", "invalid"]):
                print(f"      !! {line}")

    tn.get_socket().close()


def run_cmds_on_alpine(console_port, node_name, cmds):
    """Chạy commands trên Alpine node qua telnet."""
    print(f"\n  [telnet] {node_name} (port {console_port})...")
    try:
        tn = telnetlib.Telnet(CONSOLE_HOST, console_port, timeout=10)
    except Exception as e:
        print(f"  [!] Không kết nối được: {e}")
        return

    def drain(wait=0.5):
        time.sleep(wait)
        try:
            return tn.read_very_eager().decode(errors="ignore")
        except EOFError:
            return ""

    tn.write(b"\x03")
    drain(0.5)
    tn.write(b"\n")
    r = drain(1.0)
    if "login:" in r:
        tn.write(b"root\n")
        drain(2.0)
    tn.write(b"\n")
    drain(0.5)

    for cmd in cmds:
        print(f"    > {cmd[:70]}")
        tn.write(f"{cmd}\n".encode())
        time.sleep(0.8)
        drain(0.3)

    tn.get_socket().close()


# =============================================================================
# MAIN REFACTOR
# =============================================================================

def main():
    print("=" * 65)
    print("  12-refactor-ids-direct.py")
    print("  Hub-based TAP → Direct LEAF↔IDS + tc mirred")
    print("=" * 65)

    # ─── Tìm IDS node ─────────────────────────────────────────────────────
    ids_node = find_node("IDS-Suricata")
    if not ids_node:
        print("\n  [!] IDS-Suricata không tồn tại. Chạy 09-deploy-ids.py trước.")
        return 1
    ids_id      = ids_node["node_id"]
    ids_console = ids_node.get("console")

    hub1 = find_node("TAP-Hub1")
    hub2 = find_node("TAP-Hub2")

    # ─── Step 1: Xóa tất cả links liên quan Hub và IDS ────────────────────
    print("\n[Step 1] Xóa Hub links và IDS links...")
    hub_ids = set()
    if hub1:
        hub_ids.add(hub1["node_id"])
    if hub2:
        hub_ids.add(hub2["node_id"])
    hub_ids.add(ids_id)

    links = get_links()
    for l in links:
        for ln in l["nodes"]:
            if ln["node_id"] in hub_ids:
                delete_link(l["link_id"], f"Hub/IDS related")
                break

    # ─── Step 2: Xóa Hub nodes ────────────────────────────────────────────
    print("\n[Step 2] Xóa TAP-Hub1 và TAP-Hub2...")
    if hub1:
        stop_node(hub1["node_id"], "TAP-Hub1")
        time.sleep(0.5)
        delete_node(hub1["node_id"], "TAP-Hub1")
    if hub2:
        stop_node(hub2["node_id"], "TAP-Hub2")
        time.sleep(0.5)
        delete_node(hub2["node_id"], "TAP-Hub2")

    # ─── Step 3: Restore direct SPINE↔LEAF links ──────────────────────────
    print("\n[Step 3] Restore SPINE↔LEAF direct links...")
    # Kiểm tra link đã tồn tại chưa
    links = get_links()
    node_map = {}
    for n in get_nodes():
        node_map[n["node_id"]] = n["name"]

    spine_leaf1_exists = any(
        {node_map.get(ln["node_id"]) for ln in l["nodes"]} == {"SONIC-SPINE", "SONIC-LEAF-1"}
        for l in links
    )
    spine_leaf2_exists = any(
        {node_map.get(ln["node_id"]) for ln in l["nodes"]} == {"SONIC-SPINE", "SONIC-LEAF-2"}
        for l in links
    )

    if not spine_leaf1_exists:
        create_link(SPINE_ID, 1, 0, LEAF1_ID, 0, 0, "SPINE:eth1 ↔ LEAF-1:eth0")
    else:
        print("  [=] SPINE↔LEAF-1 link đã tồn tại")

    if not spine_leaf2_exists:
        create_link(SPINE_ID, 2, 0, LEAF2_ID, 0, 0, "SPINE:eth2 ↔ LEAF-2:eth0")
    else:
        print("  [=] SPINE↔LEAF-2 link đã tồn tại")

    # ─── Step 4: Tạo direct links LEAF↔IDS ───────────────────────────────
    print("\n[Step 4] Tạo direct links LEAF↔IDS (adapter4)...")
    # LEAF adapter4 = eth4 (NIC đã có sẵn trong QEMU, chỉ cần nối)
    create_link(LEAF1_ID, 4, 0, ids_id, 0, 0, "LEAF-1:eth4 ↔ IDS:eth0")
    create_link(LEAF2_ID, 4, 0, ids_id, 1, 0, "LEAF-2:eth4 ↔ IDS:eth1")

    # ─── Step 5: Start IDS ────────────────────────────────────────────────
    print("\n[Step 5] Start IDS-Suricata...")
    start_node(ids_id, "IDS-Suricata")
    time.sleep(2)

    # ─── Step 6: Setup eth4 trên LEAF-1 và LEAF-2 ────────────────────────
    print("\n[Step 6] Bring up eth4 trên LEAF-1 và LEAF-2...")

    leaf1_cmds = [
        "sudo ip link set eth4 up",
        "ip link show eth4 | grep -o 'state [A-Z]*'",
    ]
    leaf2_cmds = [
        "sudo ip link set eth4 up",
        "ip link show eth4 | grep -o 'state [A-Z]*'",
    ]
    run_cmds_on_sonic(LEAF1_CONSOLE, "SONIC-LEAF-1", leaf1_cmds)
    run_cmds_on_sonic(LEAF2_CONSOLE, "SONIC-LEAF-2", leaf2_cmds)

    # ─── Step 7: Config tc mirred trên LEAF-1 ────────────────────────────
    print("\n[Step 7] tc mirred trên LEAF-1 (Vlan100+Vlan200 → eth4)...")

    tc_leaf1 = []
    for vlan in LEAF1_VLANS:
        tc_leaf1 += [
            # Xóa nếu đã tồn tại (idempotent)
            f"sudo tc qdisc del dev {vlan} ingress 2>/dev/null || true",
            f"sudo tc qdisc add dev {vlan} handle ffff: ingress",
            f"sudo tc filter add dev {vlan} parent ffff: protocol ip u32 match u32 0 0 "
            f"action mirred egress mirror dev eth4",
        ]
    run_cmds_on_sonic(LEAF1_CONSOLE, "SONIC-LEAF-1 (tc mirred)", tc_leaf1)

    # ─── Step 8: Config tc mirred trên LEAF-2 ────────────────────────────
    print("\n[Step 8] tc mirred trên LEAF-2 (Vlan100+Vlan300 → eth4)...")

    tc_leaf2 = []
    for vlan in LEAF2_VLANS:
        tc_leaf2 += [
            f"sudo tc qdisc del dev {vlan} ingress 2>/dev/null || true",
            f"sudo tc qdisc add dev {vlan} handle ffff: ingress",
            f"sudo tc filter add dev {vlan} parent ffff: protocol ip u32 match u32 0 0 "
            f"action mirred egress mirror dev eth4",
        ]
    run_cmds_on_sonic(LEAF2_CONSOLE, "SONIC-LEAF-2 (tc mirred)", tc_leaf2)

    # ─── Step 9: Config IDS-Suricata promisc ─────────────────────────────
    print("\n[Step 9] Config IDS-Suricata promisc mode...")
    if ids_console:
        time.sleep(3)
        run_cmds_on_alpine(ids_console, "IDS-Suricata", [
            "ip link set eth0 up promisc on",
            "ip link set eth1 up promisc on",
            "ip addr show eth0 | grep -o PROMISC",
            "ip addr show eth1 | grep -o PROMISC",
        ])

    # ─── Done ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  REFACTOR DONE!")
    print("=" * 65)
    print("""
  Kiến trúc mới:
    SPINE ↔ LEAF-1 (direct)
    SPINE ↔ LEAF-2 (direct)
    LEAF-1:eth4 ↔ IDS:eth0  (tc mirror Vlan100+Vlan200 ingress)
    LEAF-2:eth4 ↔ IDS:eth1  (tc mirror Vlan100+Vlan300 ingress)

  Bước tiếp theo:
    1. python3 05-setup-all.py        (re-apply forwarding/routes)
    2. python3 06-verify.py           (8/8 PASS)
    3. python3 07-apply-policy.py apply
    4. python3 08-verify-policy.py    (12/12 correct)
    5. python3 11-ids-demo.py --generate
    6. Copy pcap từ IDS console hoặc dùng Suricata af-packet
  """)
    return 0


if __name__ == "__main__":
    sys.exit(main())
