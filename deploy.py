#!/usr/bin/env python3
"""
Zero Trust Microsegmentation - Full deployment script
Chạy từ GNS3 server, tự động config tất cả nodes.
Idempotent: có thể chạy lại nhiều lần, kết quả giống nhau.

GIẢ ĐỊNH: Tất cả nodes đã được START sẵn trên GNS3 UI.
Script KHÔNG đợi boot, KHÔNG start nodes.

Thứ tự:
  Phase 0: GNS3 link check only (không start, không wait)
  Phase 1: SPINE + LEAF-1 + LEAF-2 SONiC config (kernel fix included)
  Phase 2: Alpine IP config + persistence
  Phase 3: Install packages (iptables/nmap/curl)
  Phase 4: Zero Trust iptables policy
  Phase 5: Final verification

Chạy:
  python3 deploy.py              # full run
  python3 deploy.py --skip-gns3 # bỏ qua cả phase 0 (nếu links đã có)
"""

import pexpect
import time
import sys
import json
import base64
import urllib.request
import urllib.error

# ─── Config ───────────────────────────────────────────────────────────────────
GNS3_HOST   = "localhost"
GNS3_PORT   = 3080
PROJECT_ID  = "b6bf1cd6-8d58-41d4-941c-893020abd2a3"

SPINE_SSH_BOOTSTRAP = "192.168.122.187"  # IP DHCP hiện tại để SSH lần đầu
SPINE_SSH_STATIC    = "192.168.122.10"   # IP static sau khi set xong
SONIC_PASS  = "YourPaSsWoRd"
TELNET_HOST = "127.0.0.1"

# Node IDs trong GNS3
NODE_IDS = {
    "SPINE":    "7364a9ca-a155-4328-832d-fa3b818dd2e9",
    "LEAF-1":   "b49505fd-4f50-4659-bf39-9d548190663f",
    "LEAF-2":   "c62b0bdd-3bd2-4b84-a531-36450236378e",
}

# ─── Logging ──────────────────────────────────────────────────────────────────
def log(msg, level="INFO"):
    colors = {
        "INFO":  "\033[36m",
        "OK":    "\033[32m",
        "ERR":   "\033[31m",
        "STEP":  "\033[33m",
        "WARN":  "\033[35m",
    }
    reset = "\033[0m"
    print(f"{colors.get(level, '')}[{level}] {msg}{reset}", flush=True)

# ─── GNS3 REST API helpers ────────────────────────────────────────────────────
def gns3_get(path):
    url = f"http://{GNS3_HOST}:{GNS3_PORT}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def gns3_post(path, data=None):
    url = f"http://{GNS3_HOST}:{GNS3_PORT}{path}"
    body = json.dumps(data).encode() if data else b""
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

# ─── Phase 0: GNS3 link check only ───────────────────────────────────────────
def phase0_gns3_precheck():
    log("═══ Phase 0: GNS3 link check ═══", "STEP")
    log("(Giả định: nodes đã start sẵn trên UI)", "WARN")

    try:
        proj = gns3_get(f"/v2/projects/{PROJECT_ID}")
        status = proj.get("status", "unknown")
        log(f"Project status: {status}")
        if status != "opened":
            log("Project chưa mở — opening...", "WARN")
            gns3_post(f"/v2/projects/{PROJECT_ID}/open")
            time.sleep(3)
    except Exception as e:
        log(f"Cannot reach GNS3 API: {e}", "ERR")
        sys.exit(1)

    # Chỉ check/create links, KHÔNG start nodes, KHÔNG wait boot
    _ensure_links()
    log("Phase 0 done — tiến hành config ngay.", "OK")

def _ensure_links():
    """Kiểm tra và tạo lại links SPINE↔LEAF nếu bị mất."""
    log("Checking GNS3 links...")
    links = gns3_get(f"/v2/projects/{PROJECT_ID}/links")

    # Tìm các link có liên quan đến SPINE-LEAF
    spine_id   = NODE_IDS["SPINE"]
    leaf1_id   = NODE_IDS["LEAF-1"]
    leaf2_id   = NODE_IDS["LEAF-2"]

    def link_exists(node_a, adapter_a, node_b, adapter_b):
        for lnk in links:
            nodes = {n["node_id"]: n["adapter_number"] for n in lnk.get("nodes", [])}
            if nodes.get(node_a) == adapter_a and nodes.get(node_b) == adapter_b:
                return True
            if nodes.get(node_b) == adapter_a and nodes.get(node_a) == adapter_b:
                return True
        return False

    # SPINE adapter=1 (eth1) <--> LEAF-1 adapter=0 (eth0)
    if not link_exists(spine_id, 1, leaf1_id, 0):
        log("Creating link SPINE↔LEAF-1...", "WARN")
        gns3_post(f"/v2/projects/{PROJECT_ID}/links", {"nodes": [
            {"node_id": spine_id,  "adapter_number": 1, "port_number": 0},
            {"node_id": leaf1_id,  "adapter_number": 0, "port_number": 0},
        ]})
        log("Link SPINE↔LEAF-1 created", "OK")
    else:
        log("Link SPINE↔LEAF-1: OK", "OK")

    # SPINE adapter=2 (eth2) <--> LEAF-2 adapter=0 (eth0)
    if not link_exists(spine_id, 2, leaf2_id, 0):
        log("Creating link SPINE↔LEAF-2...", "WARN")
        gns3_post(f"/v2/projects/{PROJECT_ID}/links", {"nodes": [
            {"node_id": spine_id,  "adapter_number": 2, "port_number": 0},
            {"node_id": leaf2_id,  "adapter_number": 0, "port_number": 0},
        ]})
        log("Link SPINE↔LEAF-2 created", "OK")
    else:
        log("Link SPINE↔LEAF-2: OK", "OK")

# ─── Connection helpers ───────────────────────────────────────────────────────
SONIC_PROMPT = r"admin@sonic"

def ssh_connect(host, user="admin", password=SONIC_PASS, retries=5):
    for attempt in range(retries):
        try:
            log(f"SSH → {user}@{host} (attempt {attempt+1})")
            child = pexpect.spawn(
                f"sshpass -p {password} ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=10 {user}@{host}",
                timeout=30
            )
            child.expect(SONIC_PROMPT, timeout=30)
            log(f"SSH connected to {host}", "OK")
            return child
        except pexpect.TIMEOUT:
            log(f"SSH timeout attempt {attempt+1}, retrying...", "WARN")
            time.sleep(10)
    log(f"SSH FAILED after {retries} attempts to {host}", "ERR")
    sys.exit(1)

def telnet_sonic(port, retries=5):
    for attempt in range(retries):
        try:
            log(f"Telnet SONiC → {TELNET_HOST}:{port} (attempt {attempt+1})")
            child = pexpect.spawn(f"telnet {TELNET_HOST} {port}", timeout=30)
            child.expect("Connected", timeout=10)
            child.sendline("")
            time.sleep(1)
            child.sendline("")
            idx = child.expect([SONIC_PROMPT, "login:"], timeout=20)
            if idx == 1:
                child.sendline("admin")
                child.expect("Password:", timeout=10)
                child.sendline(SONIC_PASS)
                child.expect(SONIC_PROMPT, timeout=20)
            log(f"Telnet SONiC :{port} connected", "OK")
            return child
        except (pexpect.TIMEOUT, pexpect.EOF):
            log(f"Telnet attempt {attempt+1} failed, retrying...", "WARN")
            time.sleep(10)
    log(f"Telnet FAILED after {retries} attempts to :{port}", "ERR")
    sys.exit(1)

def telnet_alpine(port, retries=5):
    for attempt in range(retries):
        try:
            log(f"Telnet Alpine → {TELNET_HOST}:{port} (attempt {attempt+1})")
            child = pexpect.spawn(f"telnet {TELNET_HOST} {port}", timeout=30)
            child.expect("Connected", timeout=10)
            child.sendline("")
            idx = child.expect(["login:", r"#"], timeout=20)
            if idx == 0:
                child.sendline("root")
                child.expect(r"#", timeout=10)
            log(f"Telnet Alpine :{port} connected", "OK")
            return child
        except (pexpect.TIMEOUT, pexpect.EOF):
            log(f"Telnet attempt {attempt+1} failed, retrying...", "WARN")
            time.sleep(10)
    log(f"Telnet Alpine FAILED after {retries} attempts to :{port}", "ERR")
    sys.exit(1)

def sonic_cmd(child, cmd, timeout=30):
    """Chạy lệnh trên SONiC, chờ prompt admin@sonic"""
    child.sendline(cmd)
    child.expect(SONIC_PROMPT, timeout=timeout)
    return child.before.decode(errors="ignore").strip()

def alpine_cmd(child, cmd, timeout=60):
    """Chạy lệnh trên Alpine, chờ prompt #"""
    child.sendline(cmd)
    child.expect(r"#", timeout=timeout)
    return child.before.decode(errors="ignore").strip()

# ─── fix-routes.sh content generator ─────────────────────────────────────────
def make_fix_routes_spine():
    return r"""#!/bin/bash
sleep 90
# SPINE fix-routes: SONiC-VS kernel route conflict fix
# eth0=management, eth1=Ethernet4(→LEAF-1), eth2=Ethernet0(→LEAF-2)
sudo ip route del 10.0.1.0/30 dev Ethernet4 2>/dev/null
sudo ip route del 10.0.2.0/30 dev Ethernet0 2>/dev/null
sudo ip route del 10.0.2.0/30 dev Ethernet8 2>/dev/null
sudo ip addr add 10.0.1.1/30 dev eth1 2>/dev/null
sudo ip addr add 10.0.2.1/30 dev eth2 2>/dev/null
# Static management IP
sudo ip addr flush dev eth0
sudo ip addr add 192.168.122.10/24 dev eth0
sudo ip route add default via 192.168.122.1 2>/dev/null
"""

def make_fix_routes_leaf(uplink_subnet, host_ip, kernel_eth):
    """
    uplink_subnet: e.g. "10.0.1.0/30"  (dùng để del route sai)
    host_ip:       e.g. "10.0.1.2/30"  (IP thực của node này)
    kernel_eth:    e.g. "eth0"
    """
    return f"""#!/bin/bash
sleep 90
# LEAF fix-routes: SONiC-VS kernel route conflict fix
# {kernel_eth} = uplink to SPINE
sudo ip route del {uplink_subnet} dev Ethernet0 2>/dev/null
sudo ip addr add {host_ip} dev {kernel_eth} 2>/dev/null
"""

# ─── Helper: ghi file qua base64 (tránh lỗi heredoc trong pexpect) ────────────
def write_remote_file(child, path, content, cmd_fn):
    """Ghi file lên remote node an toàn qua base64, tránh lỗi heredoc/pexpect."""
    b64 = base64.b64encode(content.encode()).decode()
    cmd_fn(child, f"echo '{b64}' | base64 -d | sudo tee {path} > /dev/null")

# ─── Phase 1: SONiC fabric ────────────────────────────────────────────────────
def phase1_config_spine():
    log("═══ Phase 1 / TASK 1: Config SPINE ═══", "STEP")
    # Thử SSH vào IP static trước (đã set từ lần chạy trước), nếu fail thì dùng IP bootstrap
    try:
        child = ssh_connect(SPINE_SSH_STATIC)
        log("Connected via static IP (config đã có sẵn)", "OK")
    except Exception:
        log("Static IP not reachable, trying bootstrap IP...", "WARN")
        child = ssh_connect(SPINE_SSH_BOOTSTRAP)

    # SONiC control plane config
    # SPINE: Ethernet4 → LEAF-1 (10.0.1.1), Ethernet0 → LEAF-2 (10.0.2.1)
    cmds = [
        "sudo config interface ip add Ethernet4 10.0.1.1/30 2>/dev/null; true",
        "sudo config interface ip add Ethernet0 10.0.2.1/30 2>/dev/null; true",
        # Kernel fix: xóa route sai do SONiC inject
        "sudo ip route del 10.0.1.0/30 dev Ethernet4 2>/dev/null; true",
        "sudo ip route del 10.0.2.0/30 dev Ethernet0 2>/dev/null; true",
        "sudo ip route del 10.0.2.0/30 dev Ethernet8 2>/dev/null; true",
        # Thêm IP vào kernel eth đúng
        "sudo ip addr add 10.0.1.1/30 dev eth1 2>/dev/null; true",
        "sudo ip addr add 10.0.2.1/30 dev eth2 2>/dev/null; true",
        # Static routes đến VLAN subnets
        "sudo config route add prefix 10.1.0.0/16 nexthop 10.0.1.2 2>/dev/null; true",
        "sudo config route add prefix 10.2.0.0/16 nexthop 10.0.2.2 2>/dev/null; true",
        # Set static management IP qua nohup để không bị drop SSH ngay
        "ip addr show eth0 | grep -q 192.168.122.10 || (nohup bash -c 'sleep 2; ip addr flush dev eth0; ip addr add 192.168.122.10/24 dev eth0; ip route add default via 192.168.122.1' >/dev/null 2>&1 &); true",
    ]
    for cmd in cmds:
        sonic_cmd(child, cmd)

    # Tạo fix-routes.sh qua base64 (tránh lỗi heredoc)
    write_remote_file(child, "/etc/sonic/fix-routes.sh", make_fix_routes_spine(), sonic_cmd)
    sonic_cmd(child, "sudo chmod +x /etc/sonic/fix-routes.sh")
    sonic_cmd(child, r"grep -q fix-routes /etc/rc.local || sudo sed -i 's|^exit 0|/etc/sonic/fix-routes.sh \&\nexit 0|' /etc/rc.local")

    # Save config
    sonic_cmd(child, "sudo config save -y", timeout=30)

    # Verify
    out = sonic_cmd(child, "show ip interfaces | grep -E 'Ethernet|Vlan'")
    log(f"SPINE interfaces:\n{out}", "OK")
    child.close()
    # Đợi nohup apply static IP xong
    log("Chờ 5s để static IP trên SPINE apply...", "INFO")
    time.sleep(5)

def phase1_config_leaf1():
    log("═══ Phase 1 / TASK 2+5: Config LEAF-1 ═══", "STEP")
    child = telnet_sonic(5010)

    ip_out = sonic_cmd(child, "show ip interfaces")

    # Uplink
    if "10.0.1.2/30" not in ip_out:
        sonic_cmd(child, "sudo config interface ip add Ethernet0 10.0.1.2/30 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo ip route del 10.0.1.0/30 dev Ethernet0 2>/dev/null; true", timeout=10)
        sonic_cmd(child, "sudo ip addr add 10.0.1.2/30 dev eth0 2>/dev/null; true", timeout=10)
    else:
        log("LEAF-1 uplink 10.0.1.2/30 đã có — skip", "OK")

    # VLAN 100
    if "10.1.100.1/24" not in ip_out:
        sonic_cmd(child, "sudo config vlan add 100 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config vlan member add -u 100 Ethernet4 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config interface ip add Vlan100 10.1.100.1/24 2>/dev/null; true", timeout=20)
    else:
        log("LEAF-1 Vlan100 10.1.100.1/24 đã có — skip", "OK")

    # VLAN 200
    if "10.1.200.1/24" not in ip_out:
        sonic_cmd(child, "sudo config vlan add 200 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config vlan member add -u 200 Ethernet8 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config interface ip add Vlan200 10.1.200.1/24 2>/dev/null; true", timeout=20)
    else:
        log("LEAF-1 Vlan200 10.1.200.1/24 đã có — skip", "OK")

    sonic_cmd(child, "sudo config save -y", timeout=30)

    # fix-routes.sh qua base64
    write_remote_file(child, "/etc/sonic/fix-routes.sh",
                      make_fix_routes_leaf("10.0.1.0/30", "10.0.1.2/30", "eth0"),
                      sonic_cmd)
    sonic_cmd(child, "sudo chmod +x /etc/sonic/fix-routes.sh")
    sonic_cmd(child, r"grep -q fix-routes /etc/rc.local || sudo sed -i 's|^exit 0|/etc/sonic/fix-routes.sh \&\nexit 0|' /etc/rc.local")

    out = sonic_cmd(child, "show vlan brief")
    log(f"LEAF-1 VLANs:\n{out}", "OK")
    child.close()

def phase1_config_leaf2():
    log("═══ Phase 1 / TASK 3+6: Config LEAF-2 ═══", "STEP")
    child = telnet_sonic(5015)

    # Idempotency checks — skip từng bước nếu đã config đúng
    ip_out = sonic_cmd(child, "show ip interfaces")

    # Uplink
    if "10.0.2.2/30" not in ip_out:
        sonic_cmd(child, "sudo config interface ip add Ethernet0 10.0.2.2/30 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo ip route del 10.0.2.0/30 dev Ethernet0 2>/dev/null; true", timeout=10)
        sonic_cmd(child, "sudo ip addr add 10.0.2.2/30 dev eth0 2>/dev/null; true", timeout=10)
    else:
        log("LEAF-2 uplink 10.0.2.2/30 đã có — skip", "OK")

    vlan_out = sonic_cmd(child, "show vlan brief")

    # VLAN 100
    if "Vlan100" not in ip_out:
        sonic_cmd(child, "sudo config vlan add 100 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config vlan member add -u 100 Ethernet4 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config interface ip add Vlan100 10.2.100.1/24 2>/dev/null; true", timeout=20)
    else:
        log("LEAF-2 Vlan100 10.2.100.1/24 đã có — skip", "OK")

    # VLAN 300 — luôn kiểm tra IP đúng, xóa nếu sai rồi add lại
    if "10.2.50.1/24" in ip_out:
        log("LEAF-2 Vlan300 10.2.50.1/24 đã có — skip", "OK")
    else:
        # Xóa IP cũ sai (10.2.30.x hoặc /32) nếu có
        sonic_cmd(child, "sudo config interface ip remove Vlan300 10.2.30.1/24 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config interface ip remove Vlan300 10.2.30.1/32 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config vlan add 300 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config vlan member add -u 300 Ethernet8 2>/dev/null; true", timeout=20)
        sonic_cmd(child, "sudo config interface ip add Vlan300 10.2.50.1/24 2>/dev/null; true", timeout=20)

    sonic_cmd(child, "sudo config save -y", timeout=30)

    # fix-routes.sh qua base64
    write_remote_file(child, "/etc/sonic/fix-routes.sh",
                      make_fix_routes_leaf("10.0.2.0/30", "10.0.2.2/30", "eth0"),
                      sonic_cmd)
    sonic_cmd(child, "sudo chmod +x /etc/sonic/fix-routes.sh")
    sonic_cmd(child, r"grep -q fix-routes /etc/rc.local || sudo sed -i 's|^exit 0|/etc/sonic/fix-routes.sh \&\nexit 0|' /etc/rc.local")

    out = sonic_cmd(child, "show vlan brief")
    log(f"LEAF-2 VLANs:\n{out}", "OK")
    child.close()

def phase1_test_uplinks():
    log("═══ Phase 1 / TASK 4: Ping test uplinks ═══", "STEP")
    log("Chờ 5s để kernel routes ổn định...", "INFO")
    time.sleep(5)
    # Lúc này SPINE đã có static IP .10
    child = ssh_connect(SPINE_SSH_STATIC)
    all_ok = True
    for target in ["10.0.1.2", "10.0.2.2"]:
        out = sonic_cmd(child, f"ping {target} -c 3 -W 2")
        if "0% packet loss" in out:
            log(f"SPINE → {target}: OK (0% loss)", "OK")
        else:
            log(f"SPINE → {target}: FAIL\n{out}", "ERR")
            all_ok = False
    child.close()
    if not all_ok:
        log("Uplink test FAILED. Check SONiC config và kernel routes.", "ERR")
        sys.exit(1)

# ─── Phase 2: Alpine IP config ────────────────────────────────────────────────
ALPINE_HOSTS = [
    {"name": "Alpine-1", "port": 5008, "ip": "10.1.100.10/24", "gw": "10.1.100.1"},
    {"name": "Alpine-2", "port": 5011, "ip": "10.1.200.10/24", "gw": "10.1.200.1"},
    {"name": "Alpine-3", "port": 5014, "ip": "10.2.100.10/24", "gw": "10.2.100.1"},
    {"name": "Alpine-4", "port": 5016, "ip": "10.2.50.10/24",  "gw": "10.2.50.1"},
]

def phase2_config_alpine(info):
    name = info["name"]
    port = info["port"]
    ip   = info["ip"]
    gw   = info["gw"]
    ip_bare = ip.split("/")[0]  # e.g. "10.2.50.10"
    log(f"═══ Phase 2: Config {name} ({ip}) ═══", "STEP")
    try:
        child = telnet_alpine(port)
    except Exception as e:
        log(f"{name}: telnet FAIL ({e}) — skip", "WARN")
        return

    # Idempotency: nếu IP đã đúng và gateway reachable thì skip
    cur = alpine_cmd(child, "ip addr show eth0")
    gw_ok = alpine_cmd(child, f"ping {gw} -c 1 -W 1 2>/dev/null; echo $?")
    if ip_bare in cur and "0" in gw_ok.strip().splitlines()[-1:]:
        log(f"{name}: IP đã đúng ({ip}), gateway OK — skip config", "OK")
        child.close()
        return

    alpine_cmd(child, "ip addr flush dev eth0")
    alpine_cmd(child, f"ip addr add {ip} dev eth0")
    alpine_cmd(child, "ip link set eth0 up")
    alpine_cmd(child, "ip route del default 2>/dev/null; true")
    alpine_cmd(child, f"ip route add default via {gw}")

    # Persistence via /etc/local.d — ghi qua base64 tránh lỗi heredoc
    startup = (
        "#!/bin/sh\n"
        "ip addr flush dev eth0\n"
        f"ip addr add {ip} dev eth0\n"
        "ip link set eth0 up\n"
        f"ip route add default via {gw} 2>/dev/null\n"
    )
    alpine_cmd(child, "mkdir -p /etc/local.d")
    write_remote_file(child, "/etc/local.d/net.start", startup, alpine_cmd)
    alpine_cmd(child, "chmod +x /etc/local.d/net.start")
    alpine_cmd(child, "rc-update add local default 2>/dev/null; true")

    out = alpine_cmd(child, f"ping {gw} -c 2 -W 2")
    if "0% packet loss" in out:
        log(f"{name} → gateway {gw}: OK", "OK")
    else:
        log(f"{name} → gateway {gw}: FAIL\n{out}", "ERR")
    child.close()

# ─── Phase 3: Install packages ────────────────────────────────────────────────
def phase3_install_packages(info):
    name = info["name"]
    port = info["port"]
    log(f"═══ Phase 3: Install packages on {name} ═══", "STEP")
    try:
        child = telnet_alpine(port)
    except Exception as e:
        log(f"{name}: telnet FAIL ({e}) — skip", "WARN")
        return
    # Idempotency: skip nếu iptables đã có
    check = alpine_cmd(child, "which iptables 2>/dev/null; echo RC=$?")
    if "RC=0" in check:
        log(f"{name}: iptables đã có — skip apk install", "OK")
        child.close()
        return
    alpine_cmd(child, "apk update", timeout=60)
    alpine_cmd(child, "apk add -q iptables nmap curl iperf3", timeout=120)
    out = alpine_cmd(child, "iptables --version 2>/dev/null || echo NOT_FOUND")
    if "NOT_FOUND" in out:
        log(f"{name}: apk install FAIL (no internet?)", "ERR")
    else:
        log(f"{name} iptables: {out.strip()}", "OK")
    child.close()

# ─── Phase 4: Zero Trust iptables ────────────────────────────────────────────
ZTRUST_RULES = {
    # Alpine-1 (WEB): output đến DB:3306 và APP:8080
    5008: [
        "iptables -F",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT DROP",
        "iptables -A INPUT  -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -d 10.1.200.10 -p tcp --dport 3306 -j ACCEPT",  # WEB→DB
        "iptables -A OUTPUT -d 10.2.50.10 -p tcp --dport 8080 -j ACCEPT",  # WEB→APP
    ],
    # Alpine-2 (DB): chỉ nhận từ WEB1 và APP trên port 3306
    5011: [
        "iptables -F",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT DROP",
        "iptables -A INPUT  -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -s 10.1.100.10 -p tcp --dport 3306 -j ACCEPT",   # WEB1→DB
        "iptables -A INPUT -s 10.2.50.10 -p tcp --dport 3306 -j ACCEPT",   # APP→DB
    ],
    # Alpine-3 (WEB2): output đến APP:8080 và DB:3306
    5014: [
        "iptables -F",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT DROP",
        "iptables -A INPUT  -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -d 10.2.50.10 -p tcp --dport 8080 -j ACCEPT",  # WEB2→APP
        "iptables -A OUTPUT -d 10.1.200.10 -p tcp --dport 3306 -j ACCEPT",  # WEB2→DB
    ],
    # Alpine-4 (APP): nhận từ cả 2 WEB trên port 8080, output đến DB:3306
    5016: [
        "iptables -F",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT DROP",
        "iptables -A INPUT  -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -s 10.1.100.10 -p tcp --dport 8080 -j ACCEPT",   # WEB1→APP
        "iptables -A INPUT -s 10.2.100.10 -p tcp --dport 8080 -j ACCEPT",   # WEB2→APP
        "iptables -A OUTPUT -d 10.1.200.10 -p tcp --dport 3306 -j ACCEPT",  # APP→DB
    ],
}

def phase4_apply_ztrust(info):
    name = info["name"]
    port = info["port"]
    log(f"═══ Phase 4: Zero Trust {name} ═══", "STEP")
    try:
        child = telnet_alpine(port)
    except Exception as e:
        log(f"{name}: telnet FAIL ({e}) — skip", "WARN")
        return

    for rule in ZTRUST_RULES[port]:
        alpine_cmd(child, rule)

    # Persist iptables rules — ghi qua base64 tránh lỗi heredoc
    alpine_cmd(child, "mkdir -p /etc/iptables")
    alpine_cmd(child, "iptables-save > /etc/iptables/rules-save")
    restore_script = "#!/bin/sh\niptables-restore < /etc/iptables/rules-save\n"
    write_remote_file(child, "/etc/local.d/iptables.start", restore_script, alpine_cmd)
    alpine_cmd(child, "chmod +x /etc/local.d/iptables.start")

    out = alpine_cmd(child, "iptables -L -n --line-numbers | head -30")
    log(f"{name} iptables:\n{out}", "OK")
    child.close()

# ─── Phase 5: Final verification ─────────────────────────────────────────────
def phase5_verify():
    log("═══ Phase 5: Final verification ═══", "STEP")

    # Start mock servers — dùng nohup + disown để không bị kill khi telnet close
    log("Starting mock APP server on Alpine-4 (port 8080)...")
    app = telnet_alpine(5016)
    alpine_cmd(app, "pkill -f 'nc -lk -p 8080' 2>/dev/null; true")
    alpine_cmd(app, "nohup nc -lk -p 8080 </dev/null >/dev/null 2>&1 & disown")
    time.sleep(1)
    app.close()

    log("Starting mock DB server on Alpine-2 (port 3306)...")
    db = telnet_alpine(5011)
    alpine_cmd(db, "pkill -f 'nc -lk -p 3306' 2>/dev/null; true")
    alpine_cmd(db, "nohup nc -lk -p 3306 </dev/null >/dev/null 2>&1 & disown")
    time.sleep(1)
    db.close()

    time.sleep(3)  # Đợi nc bind port xong

    # Test từ Alpine-1 (WEB1)
    log("Testing from Alpine-1 (WEB1)...")
    web1 = telnet_alpine(5008)
    results = []

    # ALLOW tests
    for target, port, label in [
        ("10.2.50.10", 8080, "WEB1→APP:8080"),
        ("10.1.200.10", 3306, "WEB1→DB:3306"),
    ]:
        out = alpine_cmd(web1, f"nc -z -w 3 {target} {port} && echo PASS || echo BLOCKED", timeout=15)
        ok = "PASS" in out
        log(f"  {label}: {'ALLOW OK' if ok else 'FAIL (should be ALLOWED)'}", "OK" if ok else "ERR")
        results.append(ok)

    # DENY tests
    for target, port, label in [
        ("10.2.50.10", 9999, "WEB1→APP:9999"),
        ("10.1.200.10", 80,   "WEB1→DB:80"),
    ]:
        out = alpine_cmd(web1, f"nc -z -w 3 {target} {port} && echo PASS || echo BLOCKED", timeout=15)
        ok = "BLOCKED" in out
        log(f"  {label}: {'DENY OK' if ok else 'FAIL (should be BLOCKED)'}", "OK" if ok else "ERR")
        results.append(ok)

    web1.close()

    # Test DB không được initiate tới APP
    log("Testing from Alpine-2 (DB should NOT reach APP)...")
    db2 = telnet_alpine(5011)
    out = alpine_cmd(db2, "nc -z -w 3 10.2.50.10 8080 && echo PASS || echo BLOCKED", timeout=15)
    ok = "BLOCKED" in out
    log(f"  DB→APP:8080: {'DENY OK' if ok else 'FAIL (DB should not reach APP)'}", "OK" if ok else "ERR")
    results.append(ok)
    db2.close()

    passed = sum(results)
    total  = len(results)
    log(f"\nVerification: {passed}/{total} tests passed", "OK" if passed == total else "ERR")
    if passed < total:
        log("Some tests failed. Check iptables rules and routing.", "ERR")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    log("═══════════════════════════════════════════════", "STEP")
    log("   Zero Trust Microsegmentation Deployment     ", "STEP")
    log("═══════════════════════════════════════════════", "STEP")
    log("GIẢ ĐỊNH: Nodes đã start sẵn trên GNS3 UI", "WARN")

    try:
        # Phase 0: Chỉ check GNS3 links (không start nodes, không wait)
        if "--skip-gns3" not in sys.argv:
            phase0_gns3_precheck()
        else:
            log("Skipping phase 0 (--skip-gns3)", "WARN")

        # Phase 1: SONiC fabric
        phase1_config_spine()
        phase1_config_leaf1()
        phase1_config_leaf2()
        phase1_test_uplinks()

        # Phase 2: Alpine IP
        for host in ALPINE_HOSTS:
            phase2_config_alpine(host)

        # Phase 3: Install packages
        for host in ALPINE_HOSTS:
            phase3_install_packages(host)

        # Phase 4: Zero Trust iptables
        for host in ALPINE_HOSTS:
            phase4_apply_ztrust(host)

        # Phase 5: Verify
        phase5_verify()

        log("═══ DEPLOYMENT COMPLETE ═══", "OK")

    except KeyboardInterrupt:
        log("Interrupted by user", "WARN")
        sys.exit(1)
    except Exception as e:
        log(f"FAILED: {e}", "ERR")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()