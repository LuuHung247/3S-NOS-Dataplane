#!/usr/bin/env python3
"""
09-deploy-ids.py — Deploy Hub-based TAP IDS vào GNS3 topology
==============================================================
Chạy từ: dis@gns3vm
Chức năng: Tạo 2 Ethernet Hub (TAP) + 1 IDS-Suricata node, rewire SPINE↔LEAF
           links qua Hub để traffic được mirror tới IDS (giống SPAN port trong DC thực).

Kiến trúc sau khi deploy:
    SPINE:eth1 → TAP-Hub1 → LEAF-1:eth0   (traffic mirrored to IDS eth0)
    SPINE:eth2 → TAP-Hub2 → LEAF-2:eth0   (traffic mirrored to IDS eth1)
                    IDS-Suricata (eth0=Hub1, eth1=Hub2)

Usage:
    python3 09-deploy-ids.py           # Deploy IDS
    python3 09-deploy-ids.py --rollback  # Undo — restore direct SPINE↔LEAF links
    python3 09-deploy-ids.py --status    # Xem trạng thái hiện tại
"""

import urllib.request
import urllib.error
import json
import sys
import time
import argparse
import telnetlib

# =============================================================================
# CONFIG
# =============================================================================
GNS3_URL = "http://localhost:3080/v2"
PROJECT_ID = "b6bf1cd6-8d58-41d4-941c-893020abd2a3"

# Node IDs (đã có trong topology)
SPINE_ID  = "7364a9ca-a155-4328-832d-fa3b818dd2e9"
LEAF1_ID  = "b49505fd-4f50-4659-bf39-9d548190663f"
LEAF2_ID  = "c62b0bdd-3bd2-4b84-a531-36450236378e"

# Links hiện tại cần xóa
LINK_SPINE_LEAF1 = "251176e5-1197-427f-b404-32fe0a429188"
LINK_SPINE_LEAF2 = "408309e9-c780-408b-ae77-56d3db60ccaa"

# Templates
HUB_TEMPLATE    = "b4503ea9-d6b6-3695-9fe4-1db3b39290b0"  # Ethernet hub (built-in)
ALPINE_TEMPLATE = "23a9125b-0276-4c4b-8636-cba052e549a9"  # Alpine Linux

# Tên nodes để nhận dạng khi rollback
HUB1_NAME = "TAP-Hub1"
HUB2_NAME = "TAP-Hub2"
IDS_NAME  = "IDS-Suricata"

# Console host (gns3vm localhost)
CONSOLE_HOST = "127.0.0.1"


# =============================================================================
# GNS3 API helpers
# =============================================================================

def api_get(path):
    url = f"{GNS3_URL}{path}"
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


def api_post(path, data=None):
    url = f"{GNS3_URL}{path}"
    body = json.dumps(data or {}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"POST {path} → {e.code}: {body}") from e


def api_delete(path):
    url = f"{GNS3_URL}{path}"
    req = urllib.request.Request(url, method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            try:
                return json.load(r)
            except Exception:
                return {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # Already gone
        body = e.read().decode()
        raise RuntimeError(f"DELETE {path} → {e.code}: {body}") from e


def api_put(path, data):
    url = f"{GNS3_URL}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="PUT",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"PUT {path} → {e.code}: {body}") from e


def get_nodes():
    return api_get(f"/projects/{PROJECT_ID}/nodes")


def get_links():
    return api_get(f"/projects/{PROJECT_ID}/links")


def find_node_by_name(name):
    for n in get_nodes():
        if n["name"] == name:
            return n
    return None


def find_link_by_id(link_id):
    for l in get_links():
        if l["link_id"] == link_id:
            return l
    return None


# =============================================================================
# Step helpers
# =============================================================================

def create_node_from_template(template_id, name, x=0, y=0, extra_props=None):
    """Tạo node từ template."""
    print(f"  [+] Tạo node: {name} ...", end=" ", flush=True)
    node = api_post(f"/projects/{PROJECT_ID}/templates/{template_id}", {
        "x": x, "y": y, "compute_id": "local"
    })
    node_id = node["node_id"]

    # Đổi tên và update properties nếu cần
    update = {"name": name}
    if extra_props:
        update.update(extra_props)
    api_put(f"/projects/{PROJECT_ID}/nodes/{node_id}", update)

    print(f"OK (id={node_id[:8]}...)")
    return node_id


def create_link(node_a_id, adapter_a, port_a, node_b_id, adapter_b, port_b, label=""):
    """Tạo link giữa 2 nodes."""
    data = {
        "nodes": [
            {"node_id": node_a_id, "adapter_number": adapter_a, "port_number": port_a},
            {"node_id": node_b_id, "adapter_number": adapter_b, "port_number": port_b},
        ]
    }
    link = api_post(f"/projects/{PROJECT_ID}/links", data)
    link_id = link["link_id"]
    print(f"  [+] Link {label}: {link_id[:8]}...")
    return link_id


def start_node(node_id, name):
    print(f"  [>] Start {name} ...", end=" ", flush=True)
    api_post(f"/projects/{PROJECT_ID}/nodes/{node_id}/start")
    print("OK")


def delete_link_safe(link_id, label=""):
    result = api_delete(f"/projects/{PROJECT_ID}/links/{link_id}")
    if result is None:
        print(f"  [-] Link {label} ({link_id[:8]}...) đã không còn (skip)")
    else:
        print(f"  [-] Xóa link {label} ({link_id[:8]}...) OK")


def delete_node_safe(node_id, name):
    result = api_delete(f"/projects/{PROJECT_ID}/nodes/{node_id}")
    if result is None:
        print(f"  [-] Node {name} không tồn tại (skip)")
    else:
        print(f"  [-] Xóa node {name} OK")


# =============================================================================
# IDS Alpine: config promisc mode qua console
# =============================================================================

def configure_ids_promisc(console_port):
    """Config IDS Alpine: đặt eth0 + eth1 vào promiscuous mode."""
    print(f"\n[*] Configure IDS-Suricata (console port {console_port})...")
    time.sleep(3)  # Cho Alpine boot

    try:
        tn = telnetlib.Telnet(CONSOLE_HOST, console_port, timeout=15)
    except (ConnectionRefusedError, OSError) as e:
        print(f"  [!] Không thể kết nối console: {e}")
        print(f"  [!] Chạy thủ công sau khi boot:")
        print(f"      ip link set eth0 up promisc on")
        print(f"      ip link set eth1 up promisc on")
        return

    def drain(wait=0.5):
        time.sleep(wait)
        try:
            return tn.read_very_eager().decode(errors="ignore")
        except EOFError:
            return ""

    # Gửi Enter để kích hoạt
    tn.write(b"\x03")
    drain(0.5)
    tn.write(b"\n")
    r = drain(1.5)

    # Login nếu cần
    if "login:" in r:
        tn.write(b"root\n")
        drain(2.0)
    tn.write(b"\n")
    drain(0.5)

    cmds = [
        "ip link set eth0 up promisc on",
        "ip link set eth1 up promisc on",
        "ip addr show eth0 | grep -c PROMISC && echo eth0_promisc_ok || echo eth0_promisc_FAIL",
        "ip addr show eth1 | grep -c PROMISC && echo eth1_promisc_ok || echo eth1_promisc_FAIL",
    ]

    for cmd in cmds:
        tn.write(f"{cmd}\n".encode())
        time.sleep(1.0)
        out = drain(0.3)
        # Print kết quả nếu có info hữu ích
        for line in out.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and "~" not in line:
                if any(kw in line for kw in ["ok", "FAIL", "PROMISC", "error"]):
                    print(f"    {line}")

    tn.get_socket().close()
    print("  [+] IDS promisc config done")


# =============================================================================
# STATUS
# =============================================================================

def cmd_status():
    print("=" * 65)
    print("  GNS3 Topology Status — IDS Deployment Check")
    print("=" * 65)

    nodes = get_nodes()
    node_map = {n["node_id"]: n["name"] for n in nodes}

    # Tìm IDS nodes
    ids_nodes = [n for n in nodes if n["name"] in (HUB1_NAME, HUB2_NAME, IDS_NAME)]
    if ids_nodes:
        print("\n  IDS nodes found:")
        for n in ids_nodes:
            status = n.get("status", "?")
            console = n.get("console", "N/A")
            print(f"    [{'+' if status == 'started' else '-'}] {n['name']:<20} {status:<10} console={console}")
    else:
        print("\n  IDS nodes: NOT DEPLOYED")

    # Kiểm tra links
    links = get_links()
    print(f"\n  Links ({len(links)} total):")
    for l in links:
        ns = l["nodes"]
        if len(ns) >= 2:
            a = node_map.get(ns[0]["node_id"], ns[0]["node_id"][:8])
            b = node_map.get(ns[1]["node_id"], ns[1]["node_id"][:8])
            pa = ns[0]["adapter_number"]
            pb = ns[1]["adapter_number"]
            pna = ns[0].get("port_number", 0)
            pnb = ns[1].get("port_number", 0)
            print(f"    {a}(a{pa}p{pna}) ↔ {b}(a{pb}p{pnb})")

    print()


# =============================================================================
# DEPLOY
# =============================================================================

def cmd_deploy():
    print("=" * 65)
    print("  09-deploy-ids.py — Deploy Hub-based TAP IDS")
    print("=" * 65)

    # Kiểm tra đã deploy chưa
    existing_hub1 = find_node_by_name(HUB1_NAME)
    existing_ids  = find_node_by_name(IDS_NAME)
    if existing_hub1 or existing_ids:
        print("\n  [!] IDS nodes đã tồn tại. Dùng --status để kiểm tra.")
        print("      Nếu muốn redeploy: chạy --rollback trước.")
        return 1

    # ─── Step 1: Tạo 2 Ethernet Hub ─────────────────────────────────────────
    print("\n[Step 1] Tạo TAP-Hub1 và TAP-Hub2 (Ethernet Hub)...")

    # Hub1 nằm giữa SPINE và LEAF-1 — đặt canvas gần SPINE bên trái
    hub1_id = create_node_from_template(HUB_TEMPLATE, HUB1_NAME, x=-200, y=-100)
    # Hub2 nằm giữa SPINE và LEAF-2 — đặt canvas gần SPINE bên phải
    hub2_id = create_node_from_template(HUB_TEMPLATE, HUB2_NAME, x=200,  y=-100)

    # ─── Step 2: Tạo IDS-Suricata Alpine node ────────────────────────────────
    print("\n[Step 2] Tạo IDS-Suricata Alpine node (2 adapters)...")

    # Tạo từ template trước, sau đó update adapters = 2
    ids_id = create_node_from_template(
        ALPINE_TEMPLATE, IDS_NAME, x=0, y=100,
        extra_props={
            "properties": {
                "ram": 512,
                "cpus": 2,
                "adapters": 2,
            }
        }
    )

    # ─── Step 3: Xóa 2 link cũ SPINE↔LEAF direct ────────────────────────────
    print("\n[Step 3] Xóa direct links SPINE↔LEAF...")
    delete_link_safe(LINK_SPINE_LEAF1, "SPINE↔LEAF-1")
    delete_link_safe(LINK_SPINE_LEAF2, "SPINE↔LEAF-2")

    # ─── Step 4: Tạo 6 links mới qua Hub ─────────────────────────────────────
    print("\n[Step 4] Tạo 6 links mới qua TAP-Hub...")
    # Hub port numbering: adapter_number=0, port_number=0/1/2/...
    # SPINE adapter_number=1 → Hub1 port0
    # Hub1 port1 → LEAF-1 adapter0
    # Hub1 port2 → IDS adapter0
    # SPINE adapter_number=2 → Hub2 port0
    # Hub2 port1 → LEAF-2 adapter0
    # Hub2 port2 → IDS adapter1

    link1 = create_link(SPINE_ID,  1, 0,  hub1_id, 0, 0, "SPINE:eth1 → Hub1:port0")
    link2 = create_link(hub1_id,   0, 1,  LEAF1_ID, 0, 0, "Hub1:port1 → LEAF-1:eth0")
    link3 = create_link(hub1_id,   0, 2,  ids_id,  0, 0, "Hub1:port2 → IDS:eth0")
    link4 = create_link(SPINE_ID,  2, 0,  hub2_id, 0, 0, "SPINE:eth2 → Hub2:port0")
    link5 = create_link(hub2_id,   0, 1,  LEAF2_ID, 0, 0, "Hub2:port1 → LEAF-2:eth0")
    link6 = create_link(hub2_id,   0, 2,  ids_id,  1, 0, "Hub2:port2 → IDS:eth1")

    # Lưu link IDs để rollback
    created_links = [link1, link2, link3, link4, link5, link6]

    # ─── Step 5: Start nodes mới ─────────────────────────────────────────────
    print("\n[Step 5] Start Hub và IDS nodes...")
    start_node(hub1_id, HUB1_NAME)
    start_node(hub2_id, HUB2_NAME)
    start_node(ids_id, IDS_NAME)

    # Lấy console port của IDS
    ids_node = find_node_by_name(IDS_NAME)
    ids_console = ids_node.get("console") if ids_node else None

    # ─── Step 6: Config IDS promisc mode ─────────────────────────────────────
    if ids_console:
        configure_ids_promisc(ids_console)
    else:
        print("\n  [!] Không tìm được console port của IDS. Config thủ công sau boot.")

    # ─── Done ─────────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  DEPLOY DONE!")
    print("=" * 65)
    print(f"\n  Nodes mới:")
    print(f"    TAP-Hub1:    {hub1_id[:8]}...")
    print(f"    TAP-Hub2:    {hub2_id[:8]}...")
    print(f"    IDS-Suricata: {ids_id[:8]}...")
    if ids_console:
        print(f"\n  IDS console: telnet 112.137.129.232 {ids_console}")
    print(f"\n  Bước tiếp theo:")
    print(f"    1. python3 05-setup-all.py     (re-apply forwarding sau khi link flap)")
    print(f"    2. python3 06-verify.py         (verify 8/8 PASS — Hub transparent)")
    print(f"    3. python3 07-apply-policy.py apply  (re-apply Zero Trust)")
    print(f"    4. python3 08-verify-policy.py  (verify 12/12 correct)")
    print(f"    5. python3 10-suricata-analyze.py  (chạy Suricata)")
    return 0


# =============================================================================
# ROLLBACK
# =============================================================================

def cmd_rollback():
    print("=" * 65)
    print("  09-deploy-ids.py --rollback — Undo IDS deployment")
    print("=" * 65)
    print()

    # Tìm IDS nodes
    hub1 = find_node_by_name(HUB1_NAME)
    hub2 = find_node_by_name(HUB2_NAME)
    ids  = find_node_by_name(IDS_NAME)

    if not hub1 and not hub2 and not ids:
        print("  IDS nodes không tồn tại — topology chưa được deploy hoặc đã rollback.")
        return 0

    # ─── Stop và xóa IDS nodes (links tự xóa khi node bị xóa) ──────────────
    print("[Step 1] Stop IDS nodes...")
    for node, name in [(hub1, HUB1_NAME), (hub2, HUB2_NAME), (ids, IDS_NAME)]:
        if node:
            try:
                api_post(f"/projects/{PROJECT_ID}/nodes/{node['node_id']}/stop")
                print(f"  [>] Stop {name} OK")
            except Exception:
                pass  # Có thể đã stopped

    time.sleep(1)

    # Xóa links dính tới IDS nodes trước
    print("\n[Step 2] Xóa tất cả links của IDS/Hub nodes...")
    links = get_links()
    ids_node_ids = set()
    for n, _ in [(hub1, HUB1_NAME), (hub2, HUB2_NAME), (ids, IDS_NAME)]:
        if n:
            ids_node_ids.add(n["node_id"])

    links_to_delete = []
    for l in links:
        for ln in l["nodes"]:
            if ln["node_id"] in ids_node_ids:
                links_to_delete.append(l["link_id"])
                break

    for lid in links_to_delete:
        delete_link_safe(lid, "IDS-related")

    # Xóa nodes
    print("\n[Step 3] Xóa IDS/Hub nodes...")
    for node, name in [(hub1, HUB1_NAME), (hub2, HUB2_NAME), (ids, IDS_NAME)]:
        if node:
            delete_node_safe(node["node_id"], name)

    # ─── Tạo lại 2 links trực tiếp SPINE↔LEAF ───────────────────────────────
    print("\n[Step 4] Tạo lại direct links SPINE↔LEAF...")
    # SPINE adapter1 → LEAF-1 adapter0
    link_a = create_link(SPINE_ID, 1, 0, LEAF1_ID, 0, 0, "SPINE:eth1 ↔ LEAF-1:eth0")
    # SPINE adapter2 → LEAF-2 adapter0
    link_b = create_link(SPINE_ID, 2, 0, LEAF2_ID, 0, 0, "SPINE:eth2 ↔ LEAF-2:eth0")

    print("\n" + "=" * 65)
    print("  ROLLBACK DONE!")
    print("=" * 65)
    print(f"\n  Links mới:")
    print(f"    SPINE↔LEAF-1: {link_a[:8]}...")
    print(f"    SPINE↔LEAF-2: {link_b[:8]}...")
    print(f"\n  Bước tiếp theo (phải re-apply sau rollback):")
    print(f"    python3 05-setup-all.py && python3 06-verify.py")
    print(f"    python3 07-apply-policy.py apply && python3 08-verify-policy.py")
    return 0


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Deploy Hub-based TAP IDS vào GNS3 Spine-Leaf topology"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--rollback", action="store_true",
                     help="Undo: xóa Hub/IDS nodes, restore direct SPINE↔LEAF links")
    grp.add_argument("--status",   action="store_true",
                     help="Xem trạng thái topology hiện tại")
    args = parser.parse_args()

    if args.status:
        cmd_status()
        return 0
    elif args.rollback:
        return cmd_rollback()
    else:
        return cmd_deploy()


if __name__ == "__main__":
    sys.exit(main())
