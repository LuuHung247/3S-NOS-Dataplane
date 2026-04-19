#!/usr/bin/env python3
"""
13-fix-ids-full.py — Complete IDS fix: routing + cold-plug + Suricata install
=============================================================================
Chạy từ: dis@gns3vm

Giải quyết 2 vấn đề chính:
  1. LEAF-2 routing conflict (Ethernet0 vs eth0) → /32 host route cho SPINE
  2. IDS eth0 NO-CARRIER (QEMU hot-plug bug) → cold-plug: stop→delete→create→start

Sau đó:
  3. Setup IDS management network (10.99.1.0/24 qua LEAF-2 eth4)
  4. LEAF-2 NAT (MASQUERADE) cho IDS internet access
  5. Install Suricata trên IDS Alpine
  6. Write Suricata config + ZT rules vào IDS
  7. Start Suricata af-packet daemon
  8. Re-apply tc mirred trên cả 2 LEAF
"""

import urllib.request
import urllib.error
import json
import sys
import time
import telnetlib
import base64

# =============================================================================
# CONFIG
# =============================================================================
GNS3_URL   = "http://localhost:3080/v2"
PROJECT_ID = "b6bf1cd6-8d58-41d4-941c-893020abd2a3"

SPINE_ID  = "7364a9ca-a155-4328-832d-fa3b818dd2e9"
LEAF1_ID  = "b49505fd-4f50-4659-bf39-9d548190663f"
LEAF2_ID  = "c62b0bdd-3bd2-4b84-a531-36450236378e"

CONSOLE_HOST  = "127.0.0.1"
LEAF1_CONSOLE = 5010
LEAF2_CONSOLE = 5015
SPINE_CONSOLE = 5006

# Management network cho IDS (qua LEAF-2 eth4)
IDS_MGMT_GW  = "10.99.1.1"    # IP của LEAF-2 eth4
IDS_MGMT_IP  = "10.99.1.2"    # IP của IDS eth1 (management)
IDS_MGMT_NET = "10.99.1.0/24"

# Vlan mirrors
LEAF1_VLANS = ["Vlan100", "Vlan200"]
LEAF2_VLANS = ["Vlan100", "Vlan300"]

# Suricata config cho IDS Alpine node (af-packet mode)
IDS_SURICATA_YAML = """%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.1.0.0/16,10.2.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
af-packet:
  - interface: eth1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
  - interface: eth0
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
default-log-dir: /var/log/suricata/
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      append: yes
      types:
        - alert
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: no
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log
default-rule-path: /etc/suricata/rules
rule-files:
  - zt-lab.rules
app-layer:
  protocols:
    tls:
      enabled: yes
    dns:
      enabled: yes
    http:
      enabled: yes
detect:
  profile: low
host-mode: auto
max-pending-packets: 512
"""

ZT_RULES = (
    'alert ip 10.1.100.0/24 any -> 10.1.200.0/24 any '
    '(msg:"[ZT-VIOLATION] WEB direct to DB - microsegmentation bypass"; '
    'classtype:policy-violation; priority:1; sid:9000001; rev:1;)\n'
    'alert ip 10.1.200.0/24 any -> !10.1.200.0/24 any '
    '(msg:"[ZT-VIOLATION] DB initiating outbound connection"; '
    'classtype:policy-violation; priority:1; sid:9000002; rev:1;)\n'
    'alert ip 10.2.100.0/24 any -> 10.1.100.0/24 any '
    '(msg:"[ZT-ALERT] APP reverse call to WEB - lateral movement"; '
    'classtype:policy-violation; priority:2; sid:9000003; rev:1;)\n'
    'alert ip 10.1.100.0/24 any -> 10.2.50.0/24 any '
    '(msg:"[ZT-ALERT] WEB to MGT - unauthorized access"; '
    'classtype:policy-violation; priority:2; sid:9000004; rev:1;)\n'
    'alert ip 10.2.100.0/24 any -> 10.2.50.0/24 any '
    '(msg:"[ZT-ALERT] APP to MGT - unauthorized access"; '
    'classtype:policy-violation; priority:2; sid:9000005; rev:1;)\n'
    'alert icmp any any -> any any '
    '(msg:"[ZT-INFO] ICMP ping sweep detected"; itype:8; '
    'threshold:type both,track by_src,count 3,seconds 10; '
    'classtype:network-scan; priority:3; sid:9000010; rev:1;)\n'
    'alert tcp any any -> any any '
    '(msg:"[ZT-INFO] Possible port scan"; flags:S; '
    'threshold:type both,track by_src,count 10,seconds 5; '
    'classtype:network-scan; priority:3; sid:9000011; rev:1;)\n'
    'alert ip 10.2.50.0/24 any -> any any '
    '(msg:"[ZT-AUDIT] Management zone access"; '
    'threshold:type limit,track by_src,count 1,seconds 60; '
    'classtype:policy-violation; priority:4; sid:9000020; rev:1;)\n'
)


# =============================================================================
# GNS3 API helpers
# =============================================================================

def api(method, path, data=None):
    url = f"{GNS3_URL}{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, method=method,
        headers={"Content-Type": "application/json"} if body else {}
    )
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

def make_telnet(port, timeout=10):
    try:
        return telnetlib.Telnet(CONSOLE_HOST, port, timeout=timeout)
    except Exception as e:
        print(f"  [!] Không kết nối telnet port {port}: {e}")
        return None


def drain(tn, wait=0.5):
    time.sleep(wait)
    try:
        return tn.read_very_eager().decode(errors="ignore")
    except EOFError:
        return ""


def run_cmds_on_sonic(console_port, node_name, cmds, wait_per_cmd=1.0):
    """Chạy commands trên SONiC node qua telnet."""
    print(f"\n  [telnet→SONiC] {node_name} :{console_port}")
    tn = make_telnet(console_port)
    if not tn:
        return False

    tn.write(b"\n")
    r = drain(tn, 1.5)
    if "login:" in r:
        tn.write(b"admin\n")
        drain(tn, 1.0)
        tn.write(b"YourPaSsWoRd\n")
        drain(tn, 2.0)
    tn.write(b"\n")
    drain(tn, 0.5)

    for cmd in cmds:
        print(f"    $ {cmd[:80]}")
        tn.write(f"{cmd}\n".encode())
        time.sleep(wait_per_cmd)
        out = drain(tn, 0.3)
        for line in out.split("\n"):
            line = line.strip()
            if line and any(k in line.lower() for k in ["error", "cannot", "failed", "invalid", "unreachable"]):
                print(f"      !! {line}")
            elif line and any(k in line for k in ["PASS", "UP", "REACHABLE", "bytes from"]):
                print(f"      >> {line}")

    tn.get_socket().close()
    return True


def run_cmds_on_alpine(console_port, node_name, cmds, wait_per_cmd=1.0):
    """Chạy commands trên Alpine node qua telnet."""
    print(f"\n  [telnet→Alpine] {node_name} :{console_port}")
    tn = make_telnet(console_port)
    if not tn:
        return False

    tn.write(b"\x03")
    drain(tn, 0.5)
    tn.write(b"\n")
    r = drain(tn, 1.5)
    if "login:" in r:
        tn.write(b"root\n")
        drain(tn, 2.0)
    tn.write(b"\n")
    drain(tn, 0.5)

    for cmd in cmds:
        print(f"    $ {cmd[:80]}")
        tn.write(f"{cmd}\n".encode())
        time.sleep(wait_per_cmd)
        out = drain(tn, 0.4)
        for line in out.split("\n"):
            line = line.strip()
            if line and any(k in line.lower() for k in ["error", "failed", "no such", "permission"]):
                print(f"      !! {line}")
            elif line and any(k in line for k in ["OK", "bytes from", "PASS", "installed"]):
                print(f"      >> {line}")

    tn.get_socket().close()
    return True


def alpine_run_and_wait(console_port, node_name, cmds, wait_per_cmd=2.0, output=True):
    """Chạy commands và print output đầy đủ."""
    print(f"\n  [telnet→Alpine] {node_name} :{console_port}")
    tn = make_telnet(console_port, timeout=15)
    if not tn:
        return ""

    tn.write(b"\x03")
    drain(tn, 0.5)
    tn.write(b"\n")
    r = drain(tn, 1.5)
    if "login:" in r:
        tn.write(b"root\n")
        drain(tn, 2.0)
    tn.write(b"\n")
    drain(tn, 0.5)

    full_output = ""
    for cmd in cmds:
        print(f"    $ {cmd[:80]}")
        tn.write(f"{cmd}\n".encode())
        time.sleep(wait_per_cmd)
        out = drain(tn, 0.5)
        full_output += out
        if output:
            for line in out.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    print(f"      {line}")

    tn.get_socket().close()
    return full_output


def write_file_to_alpine(console_port, node_name, content, remote_path):
    """Ghi file tới Alpine node qua base64 chunks."""
    print(f"    [write] {remote_path} ({len(content)} bytes)...")
    tn = make_telnet(console_port)
    if not tn:
        return False

    tn.write(b"\x03")
    drain(tn, 0.5)
    tn.write(b"\n")
    r = drain(tn, 1.5)
    if "login:" in r:
        tn.write(b"root\n")
        drain(tn, 2.0)
    tn.write(b"\n")
    drain(tn, 0.5)

    b64 = base64.b64encode(content.encode()).decode()
    tmp = "/tmp/_filechunk.b64"

    # Xóa file cũ
    tn.write(f"rm -f {tmp}\n".encode())
    drain(tn, 0.3)

    # Ghi từng chunk 200 chars
    chunk_size = 200
    for i in range(0, len(b64), chunk_size):
        chunk = b64[i:i+chunk_size]
        op = ">" if i == 0 else ">>"
        tn.write(f'printf "%s" "{chunk}" {op} {tmp}\n'.encode())
        drain(tn, 0.3)

    # Decode và ghi vào đường dẫn đích
    tn.write(f"base64 -d {tmp} > {remote_path}\n".encode())
    time.sleep(0.5)
    out = drain(tn, 0.3)

    # Verify
    tn.write(f"wc -l {remote_path}\n".encode())
    time.sleep(0.4)
    out = drain(tn, 0.3)
    for line in out.split("\n"):
        if remote_path in line or line.strip().isdigit():
            print(f"      >> {line.strip()}")

    tn.get_socket().close()
    return True


# =============================================================================
# STEP 1: Fix LEAF-2 routing (Ethernet0 vs eth0 conflict)
# =============================================================================

def fix_leaf2_routing():
    print("\n[Step 1] Fix LEAF-2 routing: /32 host route cho SPINE (10.0.2.1)...")
    cmds = [
        # Xem routing table hiện tại
        "ip route show | grep 10.0.2",
        # Thêm /32 host route ép traffic qua eth0 (GNS3 link thực)
        "sudo ip route add 10.0.2.1/32 dev eth0 src 10.0.2.2 2>/dev/null"
        " || sudo ip route replace 10.0.2.1/32 dev eth0 src 10.0.2.2",
        # Verify route
        "ip route get 10.0.2.1",
        # Test ping SPINE
        "ping 10.0.2.1 -c 3 -W 2",
    ]
    run_cmds_on_sonic(LEAF2_CONSOLE, "SONIC-LEAF-2", cmds, wait_per_cmd=1.2)


# =============================================================================
# STEP 2: Setup LEAF-2 management IP + NAT cho IDS
# =============================================================================

def setup_leaf2_nat():
    print("\n[Step 2] Setup LEAF-2 eth4 management IP + NAT cho IDS...")
    cmds = [
        # Enable ip forwarding
        "sudo sysctl -w net.ipv4.ip_forward=1",
        # Gán IP cho eth4 (link tới IDS eth1)
        f"sudo ip addr add {IDS_MGMT_GW}/24 dev eth4 2>/dev/null || true",
        "sudo ip link set eth4 up",
        "ip addr show eth4",
        # FORWARD rules cho IDS subnet
        f"sudo iptables -C FORWARD -s {IDS_MGMT_NET} -j ACCEPT 2>/dev/null"
        f" || sudo iptables -I FORWARD 1 -s {IDS_MGMT_NET} -j ACCEPT",
        f"sudo iptables -C FORWARD -d {IDS_MGMT_NET} -j ACCEPT 2>/dev/null"
        f" || sudo iptables -I FORWARD 2 -d {IDS_MGMT_NET} -j ACCEPT",
        # MASQUERADE: IDS traffic ra internet qua eth0 (SPINE link)
        f"sudo iptables -t nat -C POSTROUTING -s {IDS_MGMT_NET} -o eth0 -j MASQUERADE 2>/dev/null"
        f" || sudo iptables -t nat -A POSTROUTING -s {IDS_MGMT_NET} -o eth0 -j MASQUERADE",
        # Verify
        "sudo iptables -t nat -L POSTROUTING -n | grep MASQUERADE",
    ]
    run_cmds_on_sonic(LEAF2_CONSOLE, "SONIC-LEAF-2 (NAT)", cmds, wait_per_cmd=1.0)


# =============================================================================
# STEP 3: SPINE — verify ip_forward + default route
# =============================================================================

def verify_spine_forwarding():
    print("\n[Step 3] SPINE: verify ip_forward + default route...")
    cmds = [
        "sudo sysctl -w net.ipv4.ip_forward=1",
        "ip route show default",
        "ping 8.8.8.8 -c 2 -W 3",
    ]
    run_cmds_on_sonic(SPINE_CONSOLE, "SONIC-SPINE", cmds, wait_per_cmd=1.5)


# =============================================================================
# STEP 4: Cold-plug IDS eth0 (fix NO-CARRIER)
# =============================================================================

def cold_plug_ids_eth0(ids_id):
    print("\n[Step 4] Cold-plug IDS eth0: stop → delete LEAF-1 link → create → start...")

    # Tìm link LEAF-1 ↔ IDS
    links = get_links()
    node_map = {n["node_id"]: n["name"] for n in get_nodes()}

    leaf1_ids_link = None
    for lnk in links:
        nodes_in_link = {ln["node_id"] for ln in lnk["nodes"]}
        if LEAF1_ID in nodes_in_link and ids_id in nodes_in_link:
            leaf1_ids_link = lnk
            break

    if not leaf1_ids_link:
        print("  [!] Không tìm thấy LEAF-1↔IDS link — có thể đã bị xóa trước đó")
        print("  [+] Tạo mới LEAF-1:a4 ↔ IDS:a0...")
        create_link(LEAF1_ID, 4, 0, ids_id, 0, 0, "LEAF-1:eth4 ↔ IDS:eth0")
        return

    link_id = leaf1_ids_link["link_id"]

    # Stop IDS
    print("  [>] Stop IDS-Suricata...")
    stop_node(ids_id, "IDS-Suricata")
    time.sleep(2)

    # Xóa LEAF-1↔IDS link
    delete_link(link_id, "LEAF-1:eth4 ↔ IDS:eth0")
    time.sleep(1)

    # Tạo lại link (cold-plug: IDS đang stopped)
    print("  [+] Tạo lại LEAF-1:a4 ↔ IDS:a0 (cold-plug)...")
    create_link(LEAF1_ID, 4, 0, ids_id, 0, 0, "LEAF-1:eth4 ↔ IDS:eth0")
    time.sleep(1)

    # Start IDS
    print("  [>] Start IDS-Suricata...")
    start_node(ids_id, "IDS-Suricata")
    print("  [~] Đợi IDS Alpine boot (45s)...")
    time.sleep(45)


# =============================================================================
# STEP 5: Configure IDS network
# =============================================================================

def configure_ids_network(ids_console):
    print(f"\n[Step 5] Configure IDS network (console :{ids_console})...")
    cmds = [
        # eth0: LEAF-1 mirror link (promisc, no IP needed for capture)
        "ip link set eth0 up promisc on",
        "ip link show eth0 | grep -E 'state|PROMISC'",
        # eth1: LEAF-2 mirror + management link
        "ip link set eth1 up promisc on",
        f"ip addr add {IDS_MGMT_IP}/24 dev eth1 2>/dev/null || true",
        "ip addr show eth1",
        # Default route qua LEAF-2
        f"ip route add default via {IDS_MGMT_GW} 2>/dev/null || true",
        "ip route show",
        # DNS
        "echo 'nameserver 8.8.8.8' > /etc/resolv.conf",
        "echo 'nameserver 1.1.1.1' >> /etc/resolv.conf",
    ]
    run_cmds_on_alpine(ids_console, "IDS-Suricata (network)", cmds, wait_per_cmd=0.8)


# =============================================================================
# STEP 6: Test internet từ IDS
# =============================================================================

def test_ids_internet(ids_console):
    print(f"\n[Step 6] Test internet từ IDS (console :{ids_console})...")
    cmds = [
        f"ping {IDS_MGMT_GW} -c 3 -W 2",   # ping LEAF-2
        "ping 8.8.8.8 -c 3 -W 3",           # ping internet
    ]
    out = alpine_run_and_wait(ids_console, "IDS-Suricata (internet test)", cmds,
                               wait_per_cmd=5.0, output=True)
    if "bytes from 8.8.8.8" in out or "3 packets transmitted" in out:
        print("  [OK] IDS có internet access!")
        return True
    else:
        print("  [!] IDS không ping được 8.8.8.8 — NAT/routing chưa OK")
        print("      Kiểm tra: LEAF-2 ip route get 10.0.2.1, SPINE ping 8.8.8.8")
        return False


# =============================================================================
# STEP 7: Install Suricata trên IDS Alpine
# =============================================================================

def install_suricata(ids_console):
    print(f"\n[Step 7] Install Suricata trên IDS Alpine...")

    # Enable community repo (suricata nằm ở community)
    prep_cmds = [
        "cat /etc/apk/repositories",
        # Enable community repo nếu chưa có
        "grep -q community /etc/apk/repositories"
        " || echo 'https://dl-cdn.alpinelinux.org/alpine/v3.23/community'"
        " >> /etc/apk/repositories",
        "cat /etc/apk/repositories",
    ]
    run_cmds_on_alpine(ids_console, "IDS-Suricata (apk repo)", prep_cmds, wait_per_cmd=1.0)

    print("  [~] apk update + apk add suricata (có thể mất 2-5 phút)...")
    print("  [*] Đang download/install — đợi...")

    tn = make_telnet(ids_console, timeout=30)
    if not tn:
        return False

    tn.write(b"\x03")
    drain(tn, 0.5)
    tn.write(b"\n")
    r = drain(tn, 1.5)
    if "login:" in r:
        tn.write(b"root\n")
        drain(tn, 2.0)
    tn.write(b"\n")
    drain(tn, 0.5)

    tn.write(b"apk update 2>&1 | tail -3\n")
    time.sleep(15)
    out = drain(tn, 1.0)
    print(f"      apk update: {out.strip()[-100:]}")

    tn.write(b"apk add suricata 2>&1 | tail -5\n")
    # Chờ install xong (max 5 phút)
    deadline = time.time() + 300
    print("  [~] Waiting for suricata install", end="", flush=True)
    installed = False
    while time.time() < deadline:
        time.sleep(10)
        print(".", end="", flush=True)
        out = drain(tn, 0.5)
        if "OK:" in out or "suricata" in out.lower() or "#" in out:
            print(f"\n      {out.strip()[-200:]}")
            if "error" not in out.lower() and ("ok:" in out.lower() or "installed" in out.lower()):
                installed = True
            break

    if not installed:
        print("\n  [?] Install chưa rõ kết quả, tiếp tục...")

    # Verify
    tn.write(b"suricata --version 2>&1\n")
    time.sleep(2)
    out = drain(tn, 0.5)
    if "suricata" in out.lower():
        print(f"  [OK] Suricata installed: {out.strip()[:80]}")
    else:
        print(f"  [?] {out.strip()[:120]}")

    tn.get_socket().close()
    return True


# =============================================================================
# STEP 8: Write Suricata config + rules vào IDS
# =============================================================================

def write_suricata_config(ids_console):
    print(f"\n[Step 8] Write Suricata config + ZT rules vào IDS...")

    # Tạo thư mục cần thiết
    setup_cmds = [
        "mkdir -p /etc/suricata/rules",
        "mkdir -p /var/log/suricata",
    ]
    run_cmds_on_alpine(ids_console, "IDS-Suricata (dirs)", setup_cmds, wait_per_cmd=0.5)

    # Write config
    write_file_to_alpine(ids_console, "IDS-Suricata",
                         IDS_SURICATA_YAML,
                         "/etc/suricata/suricata-zt.yaml")

    # Write rules
    write_file_to_alpine(ids_console, "IDS-Suricata",
                         ZT_RULES,
                         "/etc/suricata/rules/zt-lab.rules")

    # Verify
    verify_cmds = [
        "wc -l /etc/suricata/suricata-zt.yaml",
        "wc -l /etc/suricata/rules/zt-lab.rules",
        "grep 'af-packet' /etc/suricata/suricata-zt.yaml",
        "grep 'sid:900' /etc/suricata/rules/zt-lab.rules | wc -l",
    ]
    run_cmds_on_alpine(ids_console, "IDS-Suricata (verify config)", verify_cmds, wait_per_cmd=0.5)


# =============================================================================
# STEP 9: Start Suricata af-packet daemon
# =============================================================================

def start_suricata(ids_console):
    print(f"\n[Step 9] Start Suricata af-packet daemon...")

    cmds = [
        # Kill any running suricata
        "pkill -f suricata 2>/dev/null; sleep 1",
        # Validate config trước khi start
        "suricata -c /etc/suricata/suricata-zt.yaml -T 2>&1 | tail -5",
        # Start Suricata af-packet
        "suricata -c /etc/suricata/suricata-zt.yaml --af-packet"
        " -D --pidfile /var/run/suricata.pid 2>&1",
        "sleep 3",
        # Verify running
        "pgrep -a suricata",
        "ls -la /var/log/suricata/",
        "cat /var/log/suricata/suricata.log 2>/dev/null | tail -10",
    ]
    run_cmds_on_alpine(ids_console, "IDS-Suricata (start)", cmds, wait_per_cmd=3.0)


# =============================================================================
# STEP 10: Re-apply tc mirred trên LEAF-1 và LEAF-2
# =============================================================================

def reapply_tc_mirred():
    print("\n[Step 10] Re-apply tc mirred trên LEAF-1 + LEAF-2...")

    def build_tc_cmds(vlans):
        cmds = []
        for vlan in vlans:
            cmds += [
                f"sudo tc qdisc del dev {vlan} ingress 2>/dev/null || true",
                f"sudo tc qdisc add dev {vlan} handle ffff: ingress",
                f"sudo tc filter add dev {vlan} parent ffff: protocol ip"
                f" u32 match u32 0 0 action mirred egress mirror dev eth4",
            ]
        return cmds

    # LEAF-1
    leaf1_cmds = [
        "sudo ip link set eth4 up",
        "ip link show eth4 | grep -o 'state [A-Z]*'",
    ] + build_tc_cmds(LEAF1_VLANS) + [
        "sudo tc filter show dev Vlan100 parent ffff: | grep mirred",
    ]
    run_cmds_on_sonic(LEAF1_CONSOLE, "SONIC-LEAF-1 (tc mirred)", leaf1_cmds, wait_per_cmd=1.0)

    # LEAF-2
    leaf2_cmds = [
        "sudo ip link set eth4 up",
        "ip link show eth4 | grep -o 'state [A-Z]*'",
    ] + build_tc_cmds(LEAF2_VLANS) + [
        "sudo tc filter show dev Vlan100 parent ffff: | grep mirred",
    ]
    run_cmds_on_sonic(LEAF2_CONSOLE, "SONIC-LEAF-2 (tc mirred)", leaf2_cmds, wait_per_cmd=1.0)


# =============================================================================
# STEP 11: Quick verification
# =============================================================================

def verify_architecture(ids_console):
    print("\n[Step 11] Verify kiến trúc...")

    # Verify tc mirred on LEAF-1
    print("\n  LEAF-1 tc mirred:")
    run_cmds_on_sonic(LEAF1_CONSOLE, "SONIC-LEAF-1", [
        "sudo tc filter show dev Vlan100 parent ffff: 2>/dev/null | grep -A2 mirred | head -6",
        "sudo tc filter show dev Vlan200 parent ffff: 2>/dev/null | grep -A2 mirred | head -6",
    ], wait_per_cmd=0.8)

    # Verify tc mirred on LEAF-2
    print("\n  LEAF-2 tc mirred:")
    run_cmds_on_sonic(LEAF2_CONSOLE, "SONIC-LEAF-2", [
        "sudo tc filter show dev Vlan100 parent ffff: 2>/dev/null | grep -A2 mirred | head -6",
        "sudo tc filter show dev Vlan300 parent ffff: 2>/dev/null | grep -A2 mirred | head -6",
    ], wait_per_cmd=0.8)

    # Verify IDS
    print("\n  IDS Suricata status:")
    run_cmds_on_alpine(ids_console, "IDS-Suricata", [
        "pgrep -a suricata",
        "ip link show eth0 | grep -o 'state [A-Z]*\\|PROMISC'",
        "ip link show eth1 | grep -o 'state [A-Z]*\\|PROMISC'",
        "ls -lh /var/log/suricata/",
    ], wait_per_cmd=0.8)


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("  13-fix-ids-full.py — Complete IDS Architecture Fix")
    print("=" * 70)

    # Tìm IDS node
    print("\n[Init] Tìm IDS-Suricata node...")
    ids_node = find_node("IDS-Suricata")
    if not ids_node:
        print("  [!] IDS-Suricata không tồn tại. Chạy 09-deploy-ids.py trước.")
        return 1
    ids_id      = ids_node["node_id"]
    ids_console = ids_node.get("console")
    print(f"  [OK] IDS-Suricata: {ids_id[:8]}... console:{ids_console}")

    if not ids_console:
        print("  [!] IDS không có console port!")
        return 1

    # ─── Step 1: Fix LEAF-2 routing ──────────────────────────────────────
    fix_leaf2_routing()

    # ─── Step 2: Setup LEAF-2 NAT ────────────────────────────────────────
    setup_leaf2_nat()

    # ─── Step 3: Verify SPINE forwarding ─────────────────────────────────
    verify_spine_forwarding()

    # ─── Step 4: Cold-plug IDS eth0 ──────────────────────────────────────
    cold_plug_ids_eth0(ids_id)

    # ─── Step 5: Configure IDS network ───────────────────────────────────
    configure_ids_network(ids_console)

    # ─── Step 6: Test internet ────────────────────────────────────────────
    internet_ok = test_ids_internet(ids_console)
    if not internet_ok:
        print("\n  [!] Internet access thất bại.")
        print("  Troubleshoot:")
        print("    1. Kiểm tra SPINE có default route: ip route show default")
        print("    2. Kiểm tra LEAF-2 ip route get 10.0.2.1")
        print("    3. Kiểm tra: ping 10.0.2.1 từ LEAF-2")
        print("  Tiếp tục cài Suricata? (Ctrl+C để dừng, Enter để tiếp)")
        try:
            input()
        except KeyboardInterrupt:
            return 1

    # ─── Step 7: Install Suricata ─────────────────────────────────────────
    install_suricata(ids_console)

    # ─── Step 8: Write config + rules ────────────────────────────────────
    write_suricata_config(ids_console)

    # ─── Step 9: Start Suricata ───────────────────────────────────────────
    start_suricata(ids_console)

    # ─── Step 10: Re-apply tc mirred ─────────────────────────────────────
    reapply_tc_mirred()

    # ─── Step 11: Verify ─────────────────────────────────────────────────
    verify_architecture(ids_console)

    # ─── Done ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  DONE! Kiến trúc datacenter IDS hoàn chỉnh:")
    print("=" * 70)
    print(f"""
  Topology:
    SPINE ↔ LEAF-1 (direct)
    SPINE ↔ LEAF-2 (direct)
    LEAF-1:eth4 ↔ IDS:eth0  (tc mirror Vlan100+Vlan200 ingress)
    LEAF-2:eth4 ↔ IDS:eth1  (tc mirror Vlan100+Vlan300 ingress)

  IDS Suricata (af-packet live):
    eth0 — LEAF-1 mirror  (WEB zone + DB zone traffic)
    eth1 — LEAF-2 mirror  (APP zone + MGT zone traffic)
    Log:  /var/log/suricata/eve.json (trên IDS node)

  Bước tiếp theo (demo violations):
    1. python3 11-ids-demo.py --generate   (tạo ZT violations từ Alpine)
    2. telnet 127.0.0.1 {ids_console}      (login IDS → xem alerts)
       cat /var/log/suricata/eve.json | python3 -m json.tool | grep signature
    3. python3 11-ids-demo.py --detect     (báo cáo detection rate)
  """)
    return 0


if __name__ == "__main__":
    sys.exit(main())
