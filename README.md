# Zero Trust Microsegmentation Lab — SONiC Spine-Leaf trên GNS3

## Tiến độ

| Giai đoạn | Trạng thái | Ngày |
|-----------|-----------|------|
| Topology GNS3 (SPINE + 2 LEAF + 4 Alpine) | DONE | 2026-03-31 |
| SONiC VLAN/SVI config trên LEAF-1, LEAF-2 | DONE | 2026-04-12 |
| Same-leaf east-west routing | DONE | 2026-04-12 |
| Cross-leaf east-west routing qua SPINE | DONE | 2026-04-13 |
| **Datacenter fabric fully functional** | **DONE** | **2026-04-13** |
| Microsegmentation (iptables trên LEAF) | **DONE** | **2026-04-14** |
| Zero Trust policy (12/12 flows verified) | **DONE** | **2026-04-14** |
| Alpine nodes nâng cấp 512MB RAM, 2 vCPU | **DONE** | **2026-04-14** |
| Suricata IDS — tc mirred + af-packet live | **DONE** | **2026-04-18** |
| **Hệ thống hoàn chỉnh — 4/4 violations detected** | **DONE** | **2026-04-18** |
| IDS Alert REST API + kết nối web app | **DONE** | **2026-04-18** |
| Web Dashboard (threatcrush) — 4 pages live | **DONE** | **2026-04-19** |
| Suricata rule SC-3b APP→DB lateral movement (SID 9000006) | **DONE** | **2026-04-19** |
| iptables DNAT — IDS API expose qua 10.10.6.238:8765 | **DONE** | **2026-04-19** |
| Demo scenarios (SC-1 → SC-5) + browser test checklist | **DONE** | **2026-04-19** |
| Full end-to-end test — 5/5 SC PASS, FPR=0, 8/8 browser PASS | **DONE** | **2026-04-19** |
| Go IDS Agent — WebSocket real-time stream thay polling | **DONE** | **2026-04-19** |
| Docker Compose setup (ids-agent + nextjs) | **DONE** | **2026-04-19** |
| **nos-acl-bridge gNMI server — LEAF-1 + LEAF-2** | **DONE** | **2026-04-26** |
| Thesis documentation / evaluation | TODO | |

## Kiến trúc hiện tại — Direct LEAF↔IDS + tc mirred + Alert API

```
                       ┌──────────────────────────────┐
                       │        SONIC-SPINE           │
                       │       Console: 5006          │
                       │  eth0: 192.168.122.x (mgmt)  │
                       │  eth1: 10.0.1.1/30 → LEAF-1  │
                       │  eth2: 10.0.2.1/30 → LEAF-2  │
                       └────────────┬─────────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     ↓                             ↓
           ┌──────────────────┐         ┌──────────────────┐
           │   SONIC-LEAF-1   │         │   SONIC-LEAF-2   │
           │   Console: 5010  │         │   Console: 5015  │
           │ Vlan100:10.1.100.1│        │ Vlan100:10.2.100.1│
           │ Vlan200:10.1.200.1│        │ Vlan300:10.2.50.1 │
           │ tc mirred ↓ eth4 │         │ tc mirred ↓ eth4 │
           └──┬──┬────────────┘         └──┬──┬────────────┘
              │  │      │ mirror               │  │      │ mirror
         ┌────┴┐ ┌┴───┐ ↓              ┌─────┴┐ ┌┴───┐  ↓
         │ WEB │ │ DB │ │              │ APP  │ │MGT │  │
         │:5008│ │:5011│ │             │:5014 │ │:5016│  │
         └─────┘ └─────┘ │            └──────┘ └─────┘  │
                    eth0  └──────────────────────────────┘ eth1
                               ┌──────────────────────────────────┐
                               │         IDS-Suricata             │
                               │  Console: 5018 / RAM: 2048MB     │
                               │  Alpine 3.23 + Suricata 8.0.0    │
                               │                                  │
                               │  eth0 ← LEAF-1 mirror (WEB+DB)  │
                               │  eth1 ← LEAF-2 mirror (APP+MGT) │
                               │  eth2 → virbr0 (192.168.122.205) │
                               │         ↓ Alert REST API :8765   │
                               └──────────────────────────────────┘
                                         ↓ iptables DNAT
                               ┌──────────────────────────────────┐
                               │  112.137.129.232:8765 (public)   │
                               │  → ONAP SDNC Web App             │
                               └──────────────────────────────────┘
```

### Tại sao tc mirred tốt hơn Hub-based TAP

| | Hub TAP (cũ) | tc mirred (hiện tại) |
|--|--------------|----------------------|
| Vị trí capture | SPINE↔LEAF link | LEAF Vlan ingress |
| Timing vs iptables | SAU khi drop | TRƯỚC khi drop |
| IDS thấy violations | KHÔNG (bị drop ở LEAF) | CÓ (mirror trước drop) |
| Giống DC thực | Hub = L2 repeater đơn giản | Giống Everflow/SPAN ASIC |
| Overhead | Thêm node Hub | Kernel tc trong LEAF |

**tc mirred chạy ở ingress pipeline, trước netfilter → IDS thấy violations dù bị iptables DROP.**

### Luồng packet (WEB→DB violation):

```
WEB (10.1.100.10) → LEAF-1 Vlan100 ingress
                         ↓ tc mirred COPY
                    IDS eth0 (Suricata af-packet)  ← DETECT alert 9000001
                         ↓ packet tiếp tục
                    iptables FORWARD → DROP         ← Zero Trust BLOCK
```

## GNS3 Info

- Server: `112.137.129.232:3080`
- Project: `micro-segmentation-lab` (ID: `b6bf1cd6-8d58-41d4-941c-893020abd2a3`)
- SONiC image: `sonic-vs-30-1-2026.img` (16GB RAM, 16 CPU)
- Alpine image: `alpine-virt-3.23.0-x86_64.iso` (512MB RAM, 2 vCPU)
- SONiC login: `admin` / `YourPaSsWoRd`
- Alpine login: `root` (no password)

## Console Ports

| Node | Console | Role | IP |
|------|---------|------|----|
| SONIC-SPINE | 5006 | L3 router + NAT gateway | 10.0.1.1, 10.0.2.1 |
| SONIC-LEAF-1 | 5010 | Gateway WEB + DB + tc mirred | 10.0.1.2 (uplink) |
| SONIC-LEAF-2 | 5015 | Gateway APP + MGT + tc mirred | 10.0.2.2 (uplink) |
| Alpine-1 (WEB) | 5008 | Web server zone | 10.1.100.10 |
| Alpine-2 (DB) | 5011 | Database zone | 10.1.200.10 |
| Alpine-3 (APP) | 5014 | Application zone | 10.2.100.10 |
| Alpine-5 (MGT) | 5016 | Management zone | 10.2.50.10 |
| IDS-Suricata | 5018 | IDS (Suricata 8.0 af-packet) | 192.168.122.205 (eth2/virbr0) |

## Alert REST API — Kết nối Web App

IDS expose REST API trên port 8765 qua `eth2` (virbr0 / 192.168.122.205),
forward ra ngoài qua iptables DNAT trên gns3vm host.

### Endpoints

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/health` | GET | Status Suricata + uptime |
| `/alerts` | GET | Tất cả alerts từ eve.json (JSON) |
| `/alerts?last=N` | GET | N alerts gần nhất |
| `/stream` | GET | Server-Sent Events — real-time stream |

### Sử dụng từ ONAP SDNC / web app

```bash
# Health check
curl http://112.137.129.232:8765/health

# Lấy tất cả alerts
curl http://112.137.129.232:8765/alerts | python3 -m json.tool

# Last 20 alerts
curl http://112.137.129.232:8765/alerts?last=20
```

```javascript
// JavaScript — polling
fetch("http://112.137.129.232:8765/alerts")
  .then(r => r.json())
  .then(data => {
    console.log(data.count, "alerts");
    console.log(data.summary);   // { "9000001": 1, "9000003": 2, ... }
    data.alerts.forEach(a => console.log(a.alert.signature));
  });

// JavaScript — real-time SSE stream
const evtSrc = new EventSource("http://112.137.129.232:8765/stream");
evtSrc.onmessage = (e) => {
  const alert = JSON.parse(e.data);
  console.log(alert.alert.signature, alert.src_ip, "→", alert.dest_ip);
};
```

### Response format `/alerts`

```json
{
  "count": 16,
  "summary": {
    "9000001": 1,
    "9000002": 6,
    "9000003": 2,
    "9000004": 1,
    "9000005": 1,
    "9000010": 5
  },
  "alerts": [
    {
      "timestamp": "2026-04-18T17:15:10Z",
      "event_type": "alert",
      "src_ip": "10.1.100.10",
      "dest_ip": "10.1.200.10",
      "proto": "ICMP",
      "alert": {
        "signature": "[ZT-VIOLATION] WEB direct to DB - microsegmentation bypass",
        "signature_id": 9000001,
        "severity": 1
      }
    }
  ]
}
```

### Lưu ý — Persistence

IDS chạy Alpine **live** (không có persistent disk). Sau khi reboot IDS, cần restore:
```bash
python3 14-ids-webapi.py   # full restore: Suricata + tc mirred + Alert API
```

## Cách vận hành

### Sau khi boot/reload SONiC, chạy từ gns3vm:

```bash
cd /3s-com/zma/dc-fabric-setup

# 1. Setup fabric + forwarding tất cả nodes
python3 05-setup-all.py

# 2. Verify connectivity (8 paths, cần tất cả PASS)
python3 06-verify.py

# 3. Apply Zero Trust policy (iptables trên cả 2 LEAF)
python3 07-apply-policy.py apply

# 4. Verify microsegmentation (12 flows, cần 12/12 correct)
python3 08-verify-policy.py

# 5. Restore IDS + Suricata + Alert API (sau khi reboot IDS)
python3 14-ids-webapi.py
```

### Rollback/debug:
```bash
python3 07-apply-policy.py rollback   # Reset iptables
python3 07-apply-policy.py status     # Xem rules hiện tại
```

### Chi tiết scripts: xem [dc-fabric-setup/README.md](dc-fabric-setup/README.md)

## Root cause issues đã fix

### 1. Cross-leaf forwarding (fix sớm)
SONiC-VS chỉ set `forwarding=1` cho `EthernetX`. Kernel interfaces (`eth0`, `Vlan100`...)
có `forwarding=0` → kernel từ chối forward. Fix: enable forwarding trên tất cả interfaces.

### 2. SONiC Ethernet0 vs eth0 routing conflict (fix 2026-04-18)
SONiC-VS cài route `10.0.2.0/30 dev Ethernet0 metric 0` (NIC ảo, ARP FAILED) đè lên
`dev eth0 metric 202` (NIC thực GNS3). Fix: `/32 host route` ép traffic qua eth0:
```bash
sudo ip route add 10.0.2.1/32 dev eth0 src 10.0.2.2
```

### 4. SC-3b rule thiếu — APP→DB lateral movement không detect (fix 2026-04-19)

Suricata chỉ có 8 rules khi khởi động (SID 9000001–9000011, 9000020). Thiếu rule cho
`10.2.100.0/24 → 10.1.200.0/24` (APP→DB) — kịch bản multi-hop lateral movement quan trọng nhất của thesis.
Fix: append SID 9000006 vào `/etc/suricata/rules/3s-nos.rules` qua telnet console 5018,
reload với `kill -USR2 $(cat /var/run/suricata.pid)`. Suricata log: `9 rules successfully loaded`.

### 3. IDS internet access — double NAT (fix 2026-04-18)
IDS cần internet để `apk add suricata`. Routing: IDS → LEAF-2 MASQUERADE → SPINE MASQUERADE → Cloud.
Cần 2 tầng NAT vì GNS3 Cloud chỉ NAT traffic từ SPINE eth0 IP (192.168.122.x).

## Connectivity matrix (đã verify)

```
                 Alpine-1   Alpine-2   Alpine-3   Alpine-5
                  (WEB)      (DB)       (APP)      (MGT)
Alpine-1 (WEB)    ---      same-leaf  cross-leaf cross-leaf
Alpine-2 (DB)   same-leaf    ---      cross-leaf cross-leaf
Alpine-3 (APP)  cross-leaf cross-leaf    ---      same-leaf
Alpine-5 (MGT)  cross-leaf cross-leaf  same-leaf    ---

Tất cả 8 paths: PASS (0% packet loss)
```

## Zero Trust Microsegmentation — DONE

### Policy matrix (verified 12/12 correct)

| Source → Dest | WEB | DB | APP | MGT |
|---------------|-----|----|-----|-----|
| **WEB** | - | **DENY** | ALLOW | **DENY** |
| **DB** | **DENY** | - | **DENY** | **DENY** |
| **APP** | **DENY** | ALLOW | - | **DENY** |
| **MGT** | ALLOW | ALLOW | ALLOW | - |

### Enforcement
- `iptables` FORWARD chain trên cả LEAF-1 và LEAF-2 (defense in depth)
- SONiC ACL không enforce trên VS mode (no ASIC) → iptables thay thế
- `conntrack ESTABLISHED,RELATED` cho phép reply packets

### Verification output
```
WEB → APP   ALLOW  ALLOW  OK   Web calls backend API
WEB → DB    DENY   DENY   OK   Zero Trust: no direct web-to-db
WEB → MGT   DENY   DENY   OK   Web cannot reach management
APP → DB    ALLOW  ALLOW  OK   App queries database
APP → WEB   DENY   DENY   OK   App should not call back to web
APP → MGT   DENY   DENY   OK   App cannot reach management
DB  → WEB   DENY   DENY   OK   DB cannot initiate outbound
DB  → APP   DENY   DENY   OK   DB cannot initiate outbound
DB  → MGT   DENY   DENY   OK   DB cannot initiate outbound
MGT → WEB   ALLOW  ALLOW  OK   Management full access
MGT → DB    ALLOW  ALLOW  OK   Management full access
MGT → APP   ALLOW  ALLOW  OK   Management full access
Results: 12/12 correct — ZERO TRUST POLICY FULLY ENFORCED
```

## Suricata IDS — DONE (2026-04-18)

### Kiến trúc IDS

- **Suricata 8.0.0** chạy trên IDS-Suricata Alpine node (af-packet live capture)
- **eth0**: nhận mirror từ LEAF-1 (Vlan100 WEB + Vlan200 DB zone traffic)
- **eth1**: nhận mirror từ LEAF-2 (Vlan100 APP + Vlan300 MGT zone traffic)
- **tc mirred ingress**: copy packet TRƯỚC iptables → IDS thấy violations bị block
- **8 detection rules** (SID 9000001–9000020): violations, lateral movement, recon, audit

### Kết quả detection (verified 2026-04-18)

```
SID       Count  Priority  Alert
────────  ─────  ────────  ──────────────────────────────────────────
9000001     1x   CRITICAL  [ZT-VIOLATION] WEB direct to DB           ← DETECTED
9000002     5x   CRITICAL  [ZT-VIOLATION] DB initiating outbound     ← DETECTED
9000003     2x   HIGH      [ZT-ALERT] APP reverse call to WEB        ← DETECTED
9000004     1x   HIGH      [ZT-ALERT] WEB to MGT unauthorized        ← DETECTED
9000005     1x   HIGH      [ZT-ALERT] APP to MGT unauthorized        ← DETECTED
9000010     5x   MEDIUM    [ZT-INFO] ICMP ping sweep                 ← DETECTED

Detection rate: 4/4 expected violations — 100%
Total alerts: 15 events in eve.json
```

### Rules hiện tại — 9 rules (sau update 2026-04-19)

| SID | Rule | SC | Priority |
|---|---|---|---|
| 9000001 | `[ZT-VIOLATION] WEB direct to DB` | SC-1 | P1 CRITICAL |
| 9000002 | `[ZT-VIOLATION] DB initiating outbound connection` | SC-2 | P1 CRITICAL |
| 9000006 | `[ZT-VIOLATION] APP direct to DB - lateral movement` | **SC-3b** | **P1 CRITICAL** |
| 9000003 | `[ZT-ALERT] APP reverse call to WEB - lateral movement` | — | P2 HIGH |
| 9000004 | `[ZT-ALERT] WEB to MGT - unauthorized access` | — | P2 HIGH |
| 9000005 | `[ZT-ALERT] APP to MGT - unauthorized access` | SC-4 | P2 HIGH |
| 9000020 | `[ZT-AUDIT] Management zone access` | SC-5 | P4 AUDIT |
| 9000010 | `[ZT-INFO] ICMP ping sweep detected` | — | P3 INFO |
| 9000011 | `[ZT-INFO] Possible port scan` | SC-4 | P3 INFO |

### Demo thesis (sau mỗi lần khởi động lại):

```bash
cd /3s-com/zma/dc-fabric-setup

# Bước 1: Restore IDS network + tc mirred + Suricata
python3 13-fix-ids-full.py

# Bước 2: Generate Zero Trust violations từ Alpine nodes
python3 11-ids-demo.py --generate

# Bước 3: Xem alerts trực tiếp trên IDS (telnet console 5018)
# telnet 127.0.0.1 5018 → root (no pw)
# cat /var/log/suricata/fast.log
# cat /var/log/suricata/eve.json | grep '"msg"'
```

### tc mirred config (tự động qua 13-fix-ids-full.py):

```bash
# LEAF-1: mirror Vlan100 + Vlan200 ingress → eth4 (IDS eth0)
sudo tc qdisc add dev Vlan100 handle ffff: ingress
sudo tc filter add dev Vlan100 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4

# LEAF-2: mirror Vlan100 + Vlan300 ingress → eth4 (IDS eth1)
sudo tc qdisc add dev Vlan100 handle ffff: ingress
sudo tc filter add dev Vlan100 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4
```

### IDS management network (10.99.1.0/24):

```
IDS eth1 (10.99.1.2) → LEAF-2 eth4 (10.99.1.1) → MASQUERADE eth0
→ SPINE eth2 (10.0.2.1) → MASQUERADE eth0 → Cloud → internet
```

Dùng để: `apk add suricata`, cập nhật rules, SSH vào IDS.

## nos-acl-bridge — gNMI Dataplane API cho Secure Framework (2026-04-26)

`nos-acl-bridge` là daemon Python chạy trên mỗi SONiC LEAF, expose **gNMI server trên port 9339** với mTLS.
Secure Framework (ONAP SF / Agent-IDS) gửi `gNMI Set` → bridge ghi ConfigDB DB4 + apply iptables FORWARD.

### Kiến trúc

```
Secure Framework (ONAP SF / Agent-IDS)
        │  gNMI Set/Get/Delete  (mTLS, port 9339)
        ▼
  nos-acl-bridge (Python, /opt/nos-acl-bridge/)
        │                      │
        ▼                      ▼
  ConfigDB DB4           iptables FORWARD
  NOS_IPTABLES_RULE|*    (kernel netfilter)
```

### Trạng thái deploy

| Node | IP | Port | Status |
|------|----|------|--------|
| LEAF-1 | 192.168.122.20 | 9339 | **active** — verified 2026-04-26 |
| LEAF-2 | 192.168.122.21 | 9339 | **active** — verified 2026-04-26 |

### RBAC — mTLS client certificate (OU field)

| OU trong cert | Role | Quyền |
|---------------|------|-------|
| `internal` / `sdnc` | ADMIN | Full CRUD mọi rule |
| `aws` | OPERATOR | Get/Set nhưng không delete |
| `auto` | AGENT | Chỉ push rule `action=DROP`, `source=ids-auto` |
| Khác | DENY | Bị reject ngay |

### Cert paths

```
# Server certs (trên LEAF — tự động deploy bởi 15-deploy-bridge.py)
/etc/nos-acl-bridge/certs/server.crt
/etc/nos-acl-bridge/certs/server.key
/etc/nos-acl-bridge/certs/trustedCertificates.crt

# Client certs (trên GNS3VM — dùng để test / SF kết nối)
zma/gnmic-test/client.crt       # OU=internal → ADMIN  (smoke test)
zma/gnmic-test/client.key
zma/gnmic-test/trustedCertificates.crt
zma/agent-ids/client.crt        # OU=auto → AGENT  (Agent-IDS SF)
zma/agent-ids/client.key
```

### YANG model — nos-iptables

Module: `nos-iptables`, namespace `urn:3snos:iptables`

| Field | Type | Bắt buộc | Ghi chú |
|-------|------|----------|---------|
| `rule-id` | string (pattern `[a-zA-Z0-9_\-]{1,64}`) | Có | Key |
| `action` | `ACCEPT` \| `DROP` \| `RETURN` | Có | |
| `src-ip` | ipv4-prefix | Không | e.g. `10.1.100.5/32` |
| `dst-ip` | ipv4-prefix | Không | e.g. `10.1.200.0/24` |
| `protocol` | `tcp` \| `udp` \| `icmp` \| `all` | Không | default `all` |
| `src-port` | 1–65535 | Không | Chỉ khi protocol=tcp/udp |
| `dst-port` | 1–65535 | Không | Chỉ khi protocol=tcp/udp |
| `priority` | 1–9999 | Không | <100→top, 100–999→mid, ≥1000→append |
| `source` | `manual` \| `sdnc` \| `ids-auto` | Không | AGENT chỉ dùng `ids-auto` |
| `comment` | string ≤256 | Không | |
| `ttl-seconds` | 0–86400 | Không | 0=permanent |

### gNMI API — ví dụ gnmic

```bash
cd /3s-com/zma

# Capabilities
gnmic -a 192.168.122.20:9339 \
  --tls-cert gnmic-test/client.crt \
  --tls-key  gnmic-test/client.key \
  --tls-ca   gnmic-test/trustedCertificates.crt \
  capabilities

# Set (thêm/cập nhật rule)
cat > /tmp/rule.json << 'EOF'
{
  "rule-id": "block-web-db",
  "action": "DROP",
  "src-ip": "10.1.100.0/24",
  "dst-ip": "10.1.200.0/24",
  "protocol": "tcp",
  "priority": 100,
  "source": "sdnc",
  "comment": "ZT: WEB zone blocked to DB zone"
}
EOF

gnmic -a 192.168.122.20:9339 \
  --tls-cert gnmic-test/client.crt --tls-key gnmic-test/client.key \
  --tls-ca   gnmic-test/trustedCertificates.crt \
  -e json_ietf set \
  --update-path '/nos-iptables:acl/rule[rule-id=block-web-db]' \
  --update-file /tmp/rule.json

# Get rule
gnmic -a 192.168.122.20:9339 \
  --tls-cert gnmic-test/client.crt --tls-key gnmic-test/client.key \
  --tls-ca   gnmic-test/trustedCertificates.crt \
  get --path '/nos-iptables:acl/rule[rule-id=block-web-db]'

# Delete rule
gnmic -a 192.168.122.20:9339 \
  --tls-cert gnmic-test/client.crt --tls-key gnmic-test/client.key \
  --tls-ca   gnmic-test/trustedCertificates.crt \
  set --delete '/nos-iptables:acl/rule[rule-id=block-web-db]'

# Agent-IDS dùng cert riêng (OU=auto, chỉ DROP + source=ids-auto)
gnmic -a 192.168.122.20:9339 \
  --tls-cert agent-ids/client.crt --tls-key agent-ids/client.key \
  --tls-ca   gnmic-test/trustedCertificates.crt \
  -e json_ietf set \
  --update-path '/nos-iptables:acl/rule[rule-id=ids-block-001]' \
  --update-file /tmp/ids-rule.json
```

### Pipeline xác nhận (verified 2026-04-26)

Sau khi `gNMI Set` thành công:
```bash
# Kiểm tra ConfigDB trên LEAF (telnet 127.0.0.1 5010)
sudo redis-cli -n 4 HGETALL "NOS_IPTABLES_RULE|block-web-db"

# Kiểm tra iptables
sudo iptables -L FORWARD -n | grep "block-web-db"
# Expected: DROP  tcp -- 10.1.100.0/24  10.1.200.0/24  /* nos:block-web-db ... */

# Journal bridge
sudo journalctl -u nos-acl-bridge --no-pager -n 10
```

### Deploy / Re-deploy

```bash
cd /3s-com/zma/dc-fabric-setup

# Deploy cả 2 LEAF (khoảng 3 phút — pip install + file copy + systemd)
python3 15-deploy-bridge.py --both

# Deploy riêng lẻ
python3 15-deploy-bridge.py --leaf1   # LEAF-1 (192.168.122.20)
python3 15-deploy-bridge.py --leaf2   # LEAF-2 (192.168.122.21)
```

> **Lưu ý deploy:** SONiC LEAF không có internet → pip install lấy từ cache local.
> Script dùng `curl` (không dùng `wget` — không có trên SONiC).
> Proto stubs (`gnmi_pb2*.py`) phải generate bằng grpcio-tools **1.58** (không phải 1.70+).

### Files bridge trên LEAF

```
/opt/nos-acl-bridge/
  bridge/
    nos_acl_bridge.py   ← gNMI server chính (Capabilities/Get/Set)
    iptables.py         ← apply/remove/list iptables rules
    validators.py       ← schema validation + RBAC enforcement
    recovery.py         ← startup reconcile ConfigDB ↔ iptables
  generated/
    gnmi_pb2.py         ← Proto stubs (grpcio-tools 1.58)
    gnmi_pb2_grpc.py    ← gRPC stubs (grpcio-tools 1.58)
/etc/nos-acl-bridge/certs/
  server.crt / server.key / trustedCertificates.crt
/etc/systemd/system/nos-acl-bridge.service
```

### Source trên GNS3VM

```
/3s-com/zma/nos-acl-bridge/
  bridge/         ← Python source (sync lên LEAF qua HTTP serve)
  generated/      ← Proto stubs grpcio-tools 1.58
  nos-acl-bridge.service
/3s-com/zma/dc-fabric-setup/
  15-deploy-bridge.py   ← Deploy script
/3s-com/zma/output_3snos/sonic/
  leaf-1/{server.crt,server.key,trustedCertificates.crt}
  leaf-2/{server.crt,server.key,trustedCertificates.crt}
/3s-com/zma/gnmic-test/
  client.crt / client.key / trustedCertificates.crt  ← ADMIN cert (test)
/3s-com/zma/agent-ids/
  client.crt / client.key                            ← AGENT cert (SF)
```

---

## Web Dashboard — threatcrush (2026-04-19)

Next.js 16 dashboard tại `/3s-com/threatcrush/` + Go IDS Agent tại `/3s-com/ids-agent/`.

### Kiến trúc

```
Suricata :8765
  ├─ SSE /stream ──────→ Go Agent :8766 ──→ WebSocket /ws ──→ Browser (realtime)
  └─ REST /health /alerts → Go Agent :8766 → Next.js API routes → Browser
```

Browser kết nối WebSocket **thẳng tới Go Agent** (port 8766) — không qua Next.js.
Next.js chỉ serve frontend + proxy REST qua Go Agent.

### Pages
| Route | Mô tả |
|---|---|
| `/` | Dashboard overview — stats cards + recent 5 alerts |
| `/monitor` | Live monitor — **WebSocket realtime**, filter Zone/Priority |
| `/topology` | Spine-Leaf diagram + policy matrix |
| `/rules` | Bảng 9 Suricata ZT rules |

### API Routes (Next.js proxy → Go Agent)
| Route | Go Agent |
|---|---|
| `/api/ids/health` | `AGENT_URL/health` |
| `/api/ids/alerts?last=N` | `AGENT_URL/alerts?last=N` |

### Go IDS Agent (`/3s-com/ids-agent/`)
| Endpoint | Mô tả |
|---|---|
| `GET /health` | Proxy → Suricata `/health` |
| `GET /alerts?last=N` | Proxy → Suricata `/alerts` |
| `GET /ws` | WebSocket — broadcast realtime alerts |

Agent tự động kết nối SSE stream từ Suricata. Nếu SSE thất bại 5 lần → fallback polling 2s.
Broadcast mỗi alert JSON tới tất cả WebSocket clients đang kết nối.

### Cấu hình `.env.local`
```bash
# /3s-com/threatcrush/.env.local — CHỌN 1 profile

# Suricata IDS (luôn giữ nguyên)
IDS_API_URL=http://10.10.6.238:8765

# PROFILE 1: Local dev (ssh tunnel -L 3000:localhost:3000 -L 8766:localhost:8766)
AGENT_URL=http://localhost:8766
NEXT_PUBLIC_AGENT_WS_URL=ws://localhost:8766/ws

# PROFILE 2: ONAP master (Next.js trên 10.10.6.231, Go Agent trên 10.10.6.238)
# AGENT_URL=http://10.10.6.238:8766
# NEXT_PUBLIC_AGENT_WS_URL=ws://10.10.6.238:8766/ws

# PROFILE 3: Docker Compose
# AGENT_URL=http://ids-agent:8766
# NEXT_PUBLIC_AGENT_WS_URL=ws://<HOST_IP>:8766/ws
```

### iptables DNAT trên SONiC Node (10.10.6.238)
```bash
# Expose IDS API ra local subnet (đã apply, KHÔNG persistent sau reboot)
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8765 -j DNAT --to-destination 192.168.122.205:8765
sudo iptables -A FORWARD -p tcp -d 192.168.122.205 --dport 8765 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A OUTPUT -p tcp --dport 8765 -j DNAT --to-destination 192.168.122.205:8765

# Để persistent sau reboot:
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### Chạy thủ công
```bash
# 1. Build Go Agent (chỉ cần làm 1 lần, hoặc sau khi sửa main.go)
export PATH=$PATH:/home/dis/go/bin
cd /3s-com/ids-agent && go build -o ids-agent .

# 2. Start Go Agent
IDS_API_URL=http://10.10.6.238:8765 ./ids-agent &

# 3. Start Next.js
cd /3s-com/threatcrush
pnpm build && pnpm start

# Dev mode (Turbopack):
sudo sysctl fs.inotify.max_user_watches=524288
pnpm dev
```

### Deploy Docker Compose
```bash
# Edit docker-compose.yml: đổi <HOST_IP> thành IP máy host
cd /3s-com
docker compose up --build

# Chỉ rebuild 1 service:
docker compose up --build ids-agent
```

### Deploy lên ONAP master (10.10.6.231) — thủ công
```bash
# Copy code
rsync -av /3s-com/threatcrush/ user@10.10.6.231:/opt/threatcrush/
rsync -av /3s-com/ids-agent/   user@10.10.6.231:/opt/ids-agent/

# Trên ONAP master: dùng PROFILE 2 trong .env.local
# Go Agent vẫn chạy trên GNS3 VM (10.10.6.238), Next.js chạy trên ONAP
cd /opt/threatcrush && pnpm install && pnpm build && pnpm start
```

### Test scenarios — MITRE TA0008 Lateral Movement

| SC | Kịch bản | Technique | Expected |
|---|---|---|---|
| SC-1 | WEB→DB direct (10.1.100.10→10.1.200.10:3306) | T1021 | P1 CRITICAL, SID 9000001 |
| SC-2 | DB outbound (10.1.200.10→any) | T1071 | P1 CRITICAL, SID 9000002 |
| SC-3a | WEB→APP (ALLOW — legitimate) | — | Không có P1/P2 alert |
| SC-3b | APP→DB multi-hop (10.2.100.10→10.1.200.10) | T1210 | P1 CRITICAL, SID 9000006 |
| SC-4 | APP→MGT scan (10.2.100.10→10.2.50.x) | T1046 | P2-P3, SID 9000005/9000011 |
| SC-5 | MGT→ALL (ALLOW — baseline FPR) | — | Không có P1/P2 alert |

## Files trong project

```
/3s-com/
├── docker-compose.yml         ← Chạy ids-agent + nextjs bằng 1 lệnh
├── ids-agent/                 ← Go IDS Agent (WebSocket bridge)
│   ├── main.go                ← SSE → WebSocket hub + REST proxy
│   ├── go.mod / go.sum        ← Dependencies (gorilla/websocket)
│   ├── ids-agent              ← Binary đã build
│   └── Dockerfile             ← Multi-stage build (golang:1.22 → alpine)
├── threatcrush/               ← Next.js 16 frontend
│   ├── src/app/               ← Pages: /, /monitor, /topology, /rules
│   ├── src/app/api/ids/       ← API proxy routes → Go Agent
│   ├── .env.local             ← Config: 3 profile (local/ONAP/Docker)
│   └── Dockerfile             ← Standalone Next.js build
└── zma/
    ├── README.md              ← File này
    ├── dc-fabric-setup/       ← Scripts + docs cho DC fabric
│   ├── README.md              ← Tài liệu chi tiết kiến trúc + root cause
│   ├── 01-fix-forwarding.sh   ← Enable forwarding (chạy trên mọi SONiC node)
│   ├── 02-setup-leaf1.sh      ← Config LEAF-1 (routes + ARP)
│   ├── 03-setup-leaf2.sh      ← Config LEAF-2 (routes + ARP)
│   ├── 04-setup-spine.sh      ← Config SPINE (inter-LEAF routes)
│   ├── 05-setup-all.py        ← Tự động setup tất cả qua console
│   ├── 06-verify.py           ← Verify connectivity matrix (8 paths)
│   ├── 07-iptables-leaf1.sh   ← Zero Trust rules cho LEAF-1 (WEB+DB zones)
│   ├── 07-iptables-leaf2.sh   ← Zero Trust rules cho LEAF-2 (APP+MGT zones)
│   ├── 07-apply-policy.py     ← Apply/rollback/status iptables qua console
│   ├── 08-verify-policy.py    ← Verify microsegmentation (12 flows)
│   ├── 09-deploy-ids.py       ← (Legacy) Deploy Hub TAP + IDS node
│   ├── 10-suricata-analyze.py ← Chạy Suricata offline, parse eve.json
│   ├── 11-ids-demo.py         ← Demo: generate violations + thesis report
│   ├── 12-refactor-ids-direct.py ← Refactor Hub → direct LEAF↔IDS + tc mirred
│   ├── 13-fix-ids-full.py     ← Full restore: routing + tc mirred + Suricata
│   ├── 14-ids-webapi.py       ← IDS eth2 + Alert REST API + port-forward
│   └── suricata-ids-plan.md   ← Plan chi tiết IDS deployment
├── acl-block-db-init.json     ← ACL rule mẫu (SONiC format, ko enforce trên VS)
├── configs/                   ← SONiC config backups
├── scripts/                   ← Utility scripts
├── SONiC/                     ← SONiC related files
├── suricata/                  ← Suricata config + rules (host-side)
│   ├── suricata-zt.yaml       ← Suricata config offline pcap mode (host)
│   ├── rules/3s-nos.rules     ← Zero Trust detection rules (8 rules, sid 9000001+)
│   └── logs/                  ← eve.json, fast.log từ offline analysis
├── threatcrush/               → /3s-com/threatcrush/ (symlink)
├── gns3-canvas.py             ← Xem topology GNS3
├── gns3-ssh-info.py           ← Lấy SSH info các nodes
└── deploy.py                  ← Automation script (legacy)
```

### Suricata trên IDS Alpine node (live):
```
/etc/suricata/suricata-zt.yaml   ← af-packet config (eth0 + eth1)
/etc/suricata/rules/3s-nos.rules ← 8 ZT detection rules
/var/log/suricata/eve.json       ← Live alerts (JSON)
/var/log/suricata/fast.log       ← Live alerts (text)
/var/log/suricata/suricata.log   ← Suricata daemon log
```
