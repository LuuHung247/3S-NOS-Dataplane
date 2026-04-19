#!/usr/bin/env python3
"""
14-ids-webapi.py — Kết nối IDS với web app
============================================
Thực hiện:
  1. Stop IDS → tăng RAM lên 2048MB
  2. Nối IDS eth2 ↔ NAT1 (virbr0 direct, 192.168.122.x)
  3. Start IDS, restore Suricata
  4. Cấu hình eth2 DHCP trên IDS
  5. Deploy Alert REST API trên IDS (port 8765)
  6. Setup port-forward trên gns3vm: <public_ip>:8765 → IDS:8765

Sau khi chạy:
  ONAP WebApp → http://112.137.129.232:8765/alerts    (GET JSON)
  ONAP WebApp → http://112.137.129.232:8765/health    (health check)
  ONAP WebApp → http://112.137.129.232:8765/stream    (SSE real-time)
"""

import urllib.request, urllib.error
import json, sys, time, telnetlib, base64, subprocess

GNS3_URL   = "http://localhost:3080/v2"
PROJECT_ID = "b6bf1cd6-8d58-41d4-941c-893020abd2a3"

LEAF1_ID = "b49505fd-4f50-4659-bf39-9d548190663f"
LEAF2_ID = "c62b0bdd-3bd2-4b84-a531-36450236378e"
NAT1_ID  = "6c21053f-fe87-4047-8b08-eb328194e505"

CONSOLE_HOST = "127.0.0.1"
IDS_CONSOLE  = 5018
LEAF1_CONSOLE = 5010
LEAF2_CONSOLE = 5015
SPINE_CONSOLE = 5006

API_PORT = 8765

# =============================================================================
# Alert REST API — chạy bên trong IDS Alpine
# =============================================================================
IDS_API_SCRIPT = '''#!/usr/bin/env python3
"""
Zero Trust IDS Alert API
Endpoints:
  GET /alerts          - Tất cả alerts từ eve.json (JSON)
  GET /alerts?last=N   - N alerts gần nhất
  GET /health          - Health check
  GET /stream          - Server-Sent Events real-time stream
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, os, time, threading

EVE_FILE = "/var/log/suricata/eve.json"
API_PORT = 8765

def read_alerts(last=None):
    alerts = []
    if not os.path.exists(EVE_FILE):
        return alerts
    with open(EVE_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                if ev.get("event_type") == "alert":
                    alerts.append(ev)
            except Exception:
                pass
    if last:
        alerts = alerts[-last:]
    return alerts

class AlertHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress access logs

    def send_json(self, code, data):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        qs = self.path[len(path)+1:] if "?" in self.path else ""
        params = dict(p.split("=") for p in qs.split("&") if "=" in p)

        if path == "/health":
            suricata_running = os.path.exists("/var/run/suricata.pid")
            eve_size = os.path.getsize(EVE_FILE) if os.path.exists(EVE_FILE) else 0
            self.send_json(200, {
                "status": "ok",
                "suricata": "running" if suricata_running else "stopped",
                "eve_bytes": eve_size,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

        elif path == "/alerts":
            last = int(params.get("last", 0)) or None
            alerts = read_alerts(last)
            by_sid = {}
            for a in alerts:
                sid = str(a.get("alert", {}).get("signature_id", 0))
                by_sid[sid] = by_sid.get(sid, 0) + 1
            self.send_json(200, {
                "count": len(alerts),
                "summary": by_sid,
                "alerts": alerts,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

        elif path == "/stream":
            # Server-Sent Events — stream mỗi alert mới trong real-time
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            pos = os.path.getsize(EVE_FILE) if os.path.exists(EVE_FILE) else 0
            try:
                while True:
                    time.sleep(1)
                    if not os.path.exists(EVE_FILE):
                        continue
                    with open(EVE_FILE) as f:
                        f.seek(pos)
                        new_lines = f.read()
                        pos = f.tell()
                    for line in new_lines.strip().split("\\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                            if ev.get("event_type") == "alert":
                                data = json.dumps(ev, default=str)
                                self.wfile.write(f"data: {data}\\n\\n".encode())
                                self.wfile.flush()
                        except Exception:
                            pass
            except (BrokenPipeError, ConnectionResetError):
                pass

        else:
            self.send_json(404, {"error": "not found", "endpoints": ["/health", "/alerts", "/stream"]})


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", API_PORT), AlertHandler)
    print(f"[IDS-API] Listening on 0.0.0.0:{API_PORT}")
    print(f"[IDS-API] Endpoints: /health /alerts /alerts?last=50 /stream")
    server.serve_forever()
'''

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
            try: return json.load(r)
            except: return {}
    except urllib.error.HTTPError as e:
        if e.code == 404: return None
        raise RuntimeError(f"{method} {path} → {e.code}: {e.read().decode()}") from e


def get_nodes():
    return api("GET", f"/projects/{PROJECT_ID}/nodes")

def get_links():
    return api("GET", f"/projects/{PROJECT_ID}/links")

def find_node(name):
    return next((n for n in get_nodes() if n["name"] == name), None)

def stop_node(nid, name):
    try:
        api("POST", f"/projects/{PROJECT_ID}/nodes/{nid}/stop")
        print(f"  [>] Stop {name}")
    except: pass

def start_node(nid, name):
    api("POST", f"/projects/{PROJECT_ID}/nodes/{nid}/start")
    print(f"  [>] Start {name}")

# =============================================================================
# Telnet helpers
# =============================================================================

def drain(tn, wait=0.5):
    time.sleep(wait)
    try: return tn.read_very_eager().decode(errors="ignore")
    except EOFError: return ""

def alpine_session(port):
    tn = telnetlib.Telnet(CONSOLE_HOST, port, timeout=15)
    tn.write(b"\x03"); drain(tn, 0.5)
    tn.write(b"\n"); r = drain(tn, 1.5)
    if "login:" in r:
        tn.write(b"root\n"); drain(tn, 2.0)
    tn.write(b"\n"); drain(tn, 0.5)
    return tn

def run(tn, cmd, wait=1.0, show=True):
    tn.write(f"{cmd}\n".encode())
    time.sleep(wait)
    out = drain(tn, 0.3)
    if show:
        for l in out.split("\n"):
            l = l.strip()
            if l and not l.startswith("$"):
                print(f"    {l}")
    return out

def write_b64(tn, content, remote_path):
    b64 = base64.b64encode(content.encode()).decode()
    tmp = "/tmp/_b64"
    tn.write(f"rm -f {tmp}\n".encode()); drain(tn, 0.2)
    for i in range(0, len(b64), 150):
        op = ">" if i == 0 else ">>"
        tn.write(f'printf "%s" "{b64[i:i+150]}" {op} {tmp}\n'.encode())
        drain(tn, 0.15)
    tn.write(f"base64 -d {tmp} > {remote_path}\n".encode())
    time.sleep(0.4)
    tn.write(f"wc -c {remote_path}\n".encode()); time.sleep(0.4)
    out = drain(tn, 0.3)
    print(f"    wrote {remote_path}: {out.strip()[-50:]}")

# =============================================================================
# STEP 1: Tăng RAM IDS + nối eth2 → NAT1
# =============================================================================

def upgrade_ids_and_connect_nat():
    print("\n[Step 1] Stop IDS → tăng RAM 2048MB + nối eth2 → NAT1...")

    ids = find_node("IDS-Suricata")
    ids_id = ids["node_id"]

    # Stop IDS
    stop_node(ids_id, "IDS-Suricata")
    time.sleep(3)

    # Tăng RAM lên 2048MB
    result = api("PUT", f"/projects/{PROJECT_ID}/nodes/{ids_id}", {
        "properties": {"ram": 2048}
    })
    current_ram = result.get("properties", {}).get("ram", "?")
    print(f"  [+] IDS RAM → {current_ram}MB")

    # Tìm NAT1 port trống
    links = get_links()
    nat_used_ports = set()
    for lnk in links:
        for ln in lnk["nodes"]:
            if ln["node_id"] == NAT1_ID:
                nat_used_ports.add(ln["port_number"])
    nat_port = next(p for p in range(0, 10) if p not in nat_used_ports)

    # Tìm IDS adapter trống
    ids_used_adapters = set()
    for lnk in links:
        for ln in lnk["nodes"]:
            if ln["node_id"] == ids_id:
                ids_used_adapters.add(ln["adapter_number"])
    ids_adapter = next(a for a in range(0, 5) if a not in ids_used_adapters)

    # Tạo link NAT1 ↔ IDS (cold-plug: IDS đang stopped)
    link = api("POST", f"/projects/{PROJECT_ID}/links", {
        "nodes": [
            {"node_id": NAT1_ID,  "adapter_number": 0, "port_number": nat_port},
            {"node_id": ids_id,   "adapter_number": ids_adapter, "port_number": 0},
        ]
    })
    print(f"  [+] NAT1:port{nat_port} ↔ IDS:eth{ids_adapter} → link {link['link_id'][:8]}...")

    # Start IDS
    start_node(ids_id, "IDS-Suricata")
    print("  [~] Đợi IDS boot (45s)...")
    time.sleep(45)

    return ids_id, ids_adapter


# =============================================================================
# STEP 2: Restore Suricata + tc mirred
# =============================================================================

def restore_suricata_and_tc():
    print("\n[Step 2] Restore tc mirred + Suricata (gọi logic từ 13)...")
    import importlib.util, os
    script = os.path.join(os.path.dirname(__file__), "13-fix-ids-full.py")
    # Chạy các step cần thiết trực tiếp
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location("fix13", script)
    m = module_from_spec(spec); spec.loader.exec_module(m)

    # Routing fixes
    m.fix_leaf2_routing()
    m.setup_leaf2_nat()

    # tc mirred
    m.reapply_tc_mirred()

    # IDS network
    m.configure_ids_network(IDS_CONSOLE)

    # Suricata (đã install, chỉ cần restart)
    tn = m.make_telnet(IDS_CONSOLE)
    if tn:
        tn.write(b"\n"); drain(tn, 1.0)
        tn.write(b"pkill -f suricata 2>/dev/null; sleep 1\n"); time.sleep(2)
        tn.write(b"suricata -c /etc/suricata/suricata-zt.yaml --af-packet -D --pidfile /var/run/suricata.pid\n")
        time.sleep(5)
        out = drain(tn, 0.5)
        tn.write(b"pgrep -a suricata\n"); time.sleep(1)
        out = drain(tn, 0.5)
        if "suricata" in out:
            print("  [OK] Suricata running")
        else:
            print("  [!] Suricata không chạy — có thể cần install lại (chạy 13-fix-ids-full.py)")
        tn.get_socket().close()


# =============================================================================
# STEP 3: Configure IDS eth2 DHCP (NAT1/virbr0)
# =============================================================================

def configure_ids_eth2(ids_adapter):
    eth = f"eth{ids_adapter}"
    print(f"\n[Step 3] Configure IDS {eth} DHCP (NAT1 / 192.168.122.x)...")

    tn = alpine_session(IDS_CONSOLE)
    run(tn, f"ip link set {eth} up", 0.5)
    run(tn, f"udhcpc -i {eth} -q 2>&1", wait=8.0)
    run(tn, f"ip addr show {eth} | grep inet", 0.5)

    # Lấy IP được cấp
    tn.write(f"ip addr show {eth}\n".encode()); time.sleep(1)
    out = drain(tn, 0.5)
    import re
    m = re.search(r'inet (192\.168\.122\.\d+)', out)
    ids_eth2_ip = m.group(1) if m else None
    print(f"  [+] IDS {eth} IP: {ids_eth2_ip or '(chưa lấy được IP)'}")

    tn.get_socket().close()
    return ids_eth2_ip


# =============================================================================
# STEP 4: Deploy Alert API trên IDS
# =============================================================================

def deploy_alert_api(ids_eth2_ip):
    print(f"\n[Step 4] Deploy Alert API trên IDS (port {API_PORT})...")

    tn = alpine_session(IDS_CONSOLE)

    # Write API script
    write_b64(tn, IDS_API_SCRIPT, "/usr/local/bin/ids-api.py")
    run(tn, "chmod +x /usr/local/bin/ids-api.py", 0.3)

    # Kill existing
    run(tn, "pkill -f ids-api 2>/dev/null || true", 0.5)

    # Start API
    run(tn, f"nohup python3 /usr/local/bin/ids-api.py > /var/log/ids-api.log 2>&1 &", 1.0)
    run(tn, "sleep 2 && pgrep -a python3", 1.5)
    run(tn, f"wget -q -O- http://localhost:{API_PORT}/health 2>&1", 2.0)

    tn.get_socket().close()

    # Verify từ host
    if ids_eth2_ip:
        print(f"\n  Verify từ host → IDS {ids_eth2_ip}:{API_PORT}/health...")
        time.sleep(2)
        try:
            with urllib.request.urlopen(
                f"http://{ids_eth2_ip}:{API_PORT}/health", timeout=5
            ) as r:
                data = json.load(r)
                print(f"  [OK] API health: {data}")
        except Exception as e:
            print(f"  [!] Chưa reach được từ host: {e}")
            print(f"       Có thể cần add route: ip route add 192.168.122.0/24 dev virbr0")


# =============================================================================
# STEP 5: Port-forward trên gns3vm host
# =============================================================================

def setup_port_forward(ids_eth2_ip):
    print(f"\n[Step 5] Setup port-forward: gns3vm:8765 → IDS:{API_PORT}...")

    if not ids_eth2_ip:
        print("  [!] Không có IDS eth2 IP — skip port forward")
        return

    cmds = [
        # Enable forwarding
        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
        # DNAT: incoming → IDS
        ["sudo", "iptables", "-t", "nat", "-C", "PREROUTING",
         "-p", "tcp", "--dport", str(API_PORT), "-j", "DNAT",
         "--to-destination", f"{ids_eth2_ip}:{API_PORT}"],
    ]

    # Check if rule exists, add if not
    check = subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-C", "PREROUTING",
         "-p", "tcp", "--dport", str(API_PORT),
         "-j", "DNAT", "--to-destination", f"{ids_eth2_ip}:{API_PORT}"],
        capture_output=True
    )
    if check.returncode != 0:
        subprocess.run([
            "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "--dport", str(API_PORT),
            "-j", "DNAT", "--to-destination", f"{ids_eth2_ip}:{API_PORT}"
        ])
        print(f"  [+] DNAT rule: *:8765 → {ids_eth2_ip}:{API_PORT}")
    else:
        print(f"  [=] DNAT rule already exists")

    # FORWARD rule
    subprocess.run([
        "sudo", "iptables", "-C", "FORWARD",
        "-d", ids_eth2_ip, "-p", "tcp", "--dport", str(API_PORT), "-j", "ACCEPT"
    ], capture_output=True)
    fwd = subprocess.run(
        ["sudo", "iptables", "-C", "FORWARD",
         "-d", ids_eth2_ip, "-p", "tcp", "--dport", str(API_PORT), "-j", "ACCEPT"],
        capture_output=True
    )
    if fwd.returncode != 0:
        subprocess.run([
            "sudo", "iptables", "-A", "FORWARD",
            "-d", ids_eth2_ip, "-p", "tcp", "--dport", str(API_PORT), "-j", "ACCEPT"
        ])
        print(f"  [+] FORWARD rule: → {ids_eth2_ip}:{API_PORT}")

    # MASQUERADE cho traffic từ host → IDS (nếu cần)
    subprocess.run([
        "sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
        "-d", ids_eth2_ip, "-j", "MASQUERADE"
    ], capture_output=True)

    print(f"\n  [OK] Port forward setup:")
    print(f"       112.137.129.232:{API_PORT} → {ids_eth2_ip}:{API_PORT}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 65)
    print("  14-ids-webapi.py — Connect IDS to Web App")
    print("=" * 65)

    # Step 1: Upgrade + connect NAT1
    ids_id, ids_adapter = upgrade_ids_and_connect_nat()

    # Step 2: Restore Suricata
    try:
        restore_suricata_and_tc()
    except Exception as e:
        print(f"  [!] Restore lỗi: {e}")
        print("      Chạy thủ công: python3 13-fix-ids-full.py")

    # Step 3: eth2 DHCP
    ids_eth2_ip = configure_ids_eth2(ids_adapter)

    # Step 4: Deploy API
    deploy_alert_api(ids_eth2_ip)

    # Step 5: Port forward
    setup_port_forward(ids_eth2_ip)

    # Summary
    print("\n" + "=" * 65)
    print("  DONE — IDS Web API setup")
    print("=" * 65)
    print(f"""
  IDS network:
    eth0  ← LEAF-1 mirror (WEB+DB zone)
    eth1  ← LEAF-2 mirror (APP+MGT zone) + management
    eth2  ← NAT1/virbr0 (192.168.122.x) ← MỚI

  Alert API endpoints (từ ONAP server):
    http://112.137.129.232:{API_PORT}/health      health check
    http://112.137.129.232:{API_PORT}/alerts      all alerts (JSON)
    http://112.137.129.232:{API_PORT}/alerts?last=50  last 50 alerts
    http://112.137.129.232:{API_PORT}/stream      Server-Sent Events

  IDS RAM: 2048MB (tăng từ 1024MB)

  Sau khi reboot IDS, restore với:
    python3 14-ids-webapi.py  (hoặc 13-fix-ids-full.py nếu chỉ cần Suricata)

  Web app integration (ONAP side):
    fetch("http://112.137.129.232:{API_PORT}/alerts")
      .then(r => r.json())
      .then(data => console.log(data.count, "alerts"))

    // Real-time stream:
    const evtSrc = new EventSource("http://112.137.129.232:{API_PORT}/stream")
    evtSrc.onmessage = (e) => console.log(JSON.parse(e.data))
    """)

    return 0


if __name__ == "__main__":
    sys.exit(main())
