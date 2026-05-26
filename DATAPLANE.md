# 3S-NOS Data Plane Specification

> Document for ONAP SDNC Control Plane AI Agent
> Mục đích: cung cấp đầy đủ thông tin data plane để control plane (ONAP SDNC) implement connector tới các SONiC switch và đẩy/quản lý microsegmentation rules.

**Server**: `112.137.129.232:3080` (GNS3 server)
**Project**: `micro-segmentation-lab` — ID `b6bf1cd6-8d58-41d4-941c-893020abd2a3`
**SDNC reach data plane qua**: GNS3VM host `10.10.6.238` (LAN) hoặc `112.137.129.232` (public NAT)

---

## 1. Topology — Spine-Leaf Fabric

```
               ┌──────────────┐    ┌──────────────┐
               │     NAT1     │    │     NAT2     │
               │ (Cloud/Mgmt) │    │   (GNS3VM)   │
               └──────┬───────┘    └───────┬──────┘
                      │                    │
                ┌─────┴────────────────────┴─────┐
                │         SONIC-SPINE             │
                │   eth0: 192.168.122.x (mgmt)   │
                │   eth1: 10.0.1.1/30 → LEAF-1   │
                │   eth2: 10.0.2.1/30 → LEAF-2   │
                └────────┬───────────────┬────────┘
                         │               │
              ┌──────────┘               └──────────┐
     ┌────────┴─────────┐               ┌───────────┴──────┐
     │   SONIC-LEAF-1   │               │   SONIC-LEAF-2   │
     │ uplink eth0:     │               │ uplink eth0:     │
     │   10.0.1.2/30    │               │   10.0.2.2/30    │
     │ Vlan100 SVI:     │               │ Vlan100 SVI:     │
     │   10.1.100.1/24  │               │   10.2.100.1/24  │
     │ Vlan200 SVI:     │               │ Vlan300 SVI:     │
     │   10.1.200.1/24  │               │   10.2.50.1/24   │
     │ tc mirred → eth4 │               │ tc mirred → eth4 │
     └──┬───┬───────┬───┘               └──┬───┬───────┬───┘
        │   │       │ mirror               │   │       │ mirror
        │   │       └────────────┐  ┌──────┘   │       │
       ┌┴┐ ┌┴┐                   ↓  ↓         ┌┴┐ ┌┴┐
       │W│ │D│                ┌─────────┐    │A│ │M│
       │E│ │B│                │   IDS   │    │P│ │G│
       │B│ └─┘                │ Suricata│    │P│ │T│
       └─┘                    └─────────┘    └─┘ └─┘
```

---

## 2. Node Inventory

| Node | Type | GNS3 Console | Mgmt IP | Role |
|------|------|--------------|---------|------|
| SONIC-SPINE | SONiC-VS | `telnet 112.137.129.232:5006` | 192.168.122.x (DHCP) | L3 core router, inter-LEAF transit |
| SONIC-LEAF-1 | SONiC-VS | `telnet 112.137.129.232:5010` | 192.168.122.x (DHCP) | Gateway WEB+DB, ZT enforcement |
| SONIC-LEAF-2 | SONiC-VS | `telnet 112.137.129.232:5015` | 192.168.122.x (DHCP) | Gateway APP+MGT, ZT enforcement |
| Alpine-Linux-1 | Alpine 3.23 | `telnet 112.137.129.232:5008` | 10.1.100.10/24 | WEB zone host |
| Alpine-Linux-2 | Alpine 3.23 | `telnet 112.137.129.232:5011` | 10.1.200.10/24 | DB zone host |
| Alpine-Linux-3 | Alpine 3.23 | `telnet 112.137.129.232:5014` | 10.2.100.10/24 | APP zone host |
| Alpine-Linux-5 | Alpine 3.23 | `telnet 112.137.129.232:5016` | 10.2.50.10/24 | MGT zone host |
| IDS-Suricata | Alpine 3.23 + Suricata 8.0 | `telnet 112.137.129.232:5018` | 192.168.122.205 (eth2) | IDS, REST API :8765 |

**Login credentials:**
- SONiC: `admin` / `YourPaSsWoRd`
- Alpine: `root` (no password)

---

## 3. Layer 3 — IP Address Plan

### 3.1 Underlay (point-to-point /30)

| Link | SPINE side | LEAF side |
|------|-----------|-----------|
| SPINE ↔ LEAF-1 | `10.0.1.1/30` (eth1) | `10.0.1.2/30` (eth0) |
| SPINE ↔ LEAF-2 | `10.0.2.1/30` (eth2) | `10.0.2.2/30` (eth0) |

### 3.2 Overlay — VLAN/SVI per zone

| Zone | LEAF | VLAN | SVI Gateway | CIDR | Host |
|------|------|------|-------------|------|------|
| **WEB** | LEAF-1 | Vlan100 | 10.1.100.1 | 10.1.100.0/24 | Alpine-1: 10.1.100.10 |
| **DB**  | LEAF-1 | Vlan200 | 10.1.200.1 | 10.1.200.0/24 | Alpine-2: 10.1.200.10 |
| **APP** | LEAF-2 | Vlan100 | 10.2.100.1 | 10.2.100.0/24 | Alpine-3: 10.2.100.10 |
| **MGT** | LEAF-2 | Vlan300 | 10.2.50.1  | 10.2.50.0/24  | Alpine-5: 10.2.50.10 |

### 3.3 Out-of-band — Management

| Interface | IP | Mục đích |
|-----------|-----|----------|
| GNS3VM host eth0 | 10.10.6.238 (LAN) / 112.137.129.232 (public NAT) | SDNC NETCONF/SSH entrypoint |
| virbr0 (libvirt bridge) | 192.168.122.1/24 | Mgmt network — SONiC mgmt + IDS eth2 |
| IDS-Suricata eth2 | 192.168.122.205 | Alert REST API exposure |

---

## 4. Routing — Forwarding Plane

**Mechanism:** Static routes + kernel `ip forwarding=1` trên tất cả interfaces (SONiC-VS không có ASIC, dùng Linux kernel forwarding).

### 4.1 SONIC-SPINE routing table

```
10.0.1.0/30 dev eth1            # to LEAF-1 underlay
10.0.2.0/30 dev eth2            # to LEAF-2 underlay
10.1.100.0/24 via 10.0.1.2      # WEB zone via LEAF-1
10.1.200.0/24 via 10.0.1.2      # DB zone via LEAF-1
10.2.100.0/24 via 10.0.2.2      # APP zone via LEAF-2
10.2.50.0/24  via 10.0.2.2      # MGT zone via LEAF-2
```

### 4.2 SONIC-LEAF-1 routing table

```
10.0.1.0/30 dev eth0            # underlay to SPINE
10.1.100.0/24 dev Vlan100       # WEB direct
10.1.200.0/24 dev Vlan200       # DB direct
10.2.100.0/24 via 10.0.1.1      # APP via SPINE
10.2.50.0/24  via 10.0.1.1      # MGT via SPINE
default via 10.0.1.1            # all else via SPINE
```

### 4.3 SONIC-LEAF-2 routing table

```
10.0.2.0/30 dev eth0            # underlay to SPINE
10.2.100.0/24 dev Vlan100       # APP direct
10.2.50.0/24  dev Vlan300       # MGT direct
10.1.100.0/24 via 10.0.2.1      # WEB via SPINE
10.1.200.0/24 via 10.0.2.1      # DB via SPINE
default via 10.0.2.1
```

### 4.4 Critical fix — SONiC-VS host route

SONiC-VS install route `10.0.X.0/30 dev EthernetX metric 0` (NIC ảo, ARP fail) đè lên `dev eth0`. Cần inject `/32` host route:

```bash
sudo ip route add 10.0.2.1/32 dev eth0 src 10.0.2.2  # trên LEAF-2
sudo ip route add 10.0.1.1/32 dev eth0 src 10.0.1.2  # trên LEAF-1
```

---

## 5. Microsegmentation — Zero Trust Policy

### 5.1 Policy Matrix (nguồn → đích)

| Source ↓ \ Dest → | WEB | DB | APP | MGT |
|---|:---:|:---:|:---:|:---:|
| **WEB** | — | **DENY** | ALLOW | **DENY** |
| **DB**  | **DENY** | — | **DENY** | **DENY** |
| **APP** | **DENY** | ALLOW | — | **DENY** |
| **MGT** | ALLOW | ALLOW | ALLOW | — |

**Verified:** 12/12 flows enforce correct.

### 5.2 Enforcement Point

- **Where:** `iptables FORWARD chain` trên LEAF-1 và LEAF-2 (defense-in-depth — cả 2 LEAF apply rule giống nhau cho flows liên quan).
- **Why iptables, không phải SONiC ACL:** SONiC-VS chạy mode software, không có ASIC để enforce ACL → fallback Linux kernel netfilter.
- **State tracking:** `conntrack` module enabled; rule `ESTABLISHED,RELATED ACCEPT` trước các DROP rule để cho phép reply traffic.

### 5.3 iptables Rules — LEAF-1 (WEB + DB zones)

```bash
# Default policy
iptables -P FORWARD DROP

# Conntrack — cho phép reply
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# === ZT POLICY: WEB zone (10.1.100.0/24) ===
iptables -A FORWARD -s 10.1.100.0/24 -d 10.1.200.0/24 -j DROP   # WEB→DB BLOCK
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.50.0/24  -j DROP   # WEB→MGT BLOCK
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.100.0/24 -j ACCEPT # WEB→APP ALLOW

# === ZT POLICY: DB zone (10.1.200.0/24) — outbound DENY-ALL ===
iptables -A FORWARD -s 10.1.200.0/24 -d 10.1.100.0/24 -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -d 10.2.100.0/24 -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -d 10.2.50.0/24  -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -j DROP

# === Inbound to DB — only from APP ===
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.200.0/24 -j ACCEPT  # APP→DB ALLOW
iptables -A FORWARD -s 10.2.50.0/24  -d 10.1.200.0/24 -j ACCEPT  # MGT→DB ALLOW

# Drop everything else
iptables -A FORWARD -j DROP
```

### 5.4 iptables Rules — LEAF-2 (APP + MGT zones)

```bash
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# === ZT POLICY: APP zone (10.2.100.0/24) ===
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.100.0/24 -j DROP   # APP→WEB BLOCK (reverse call)
iptables -A FORWARD -s 10.2.100.0/24 -d 10.2.50.0/24  -j DROP   # APP→MGT BLOCK
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.200.0/24 -j ACCEPT # APP→DB ALLOW

# === ZT POLICY: MGT zone (10.2.50.0/24) — full access ===
iptables -A FORWARD -s 10.2.50.0/24 -j ACCEPT

# === Inbound to APP — from WEB only ===
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.100.0/24 -j ACCEPT  # WEB→APP ALLOW

iptables -A FORWARD -j DROP
```

### 5.5 Apply / Rollback / Status

Hiện tại quản lý qua Python helper:

```bash
cd /3s-com/zma/dc-fabric-setup
python3 07-apply-policy.py apply      # push iptables qua console
python3 07-apply-policy.py rollback   # iptables -F FORWARD && -P ACCEPT
python3 07-apply-policy.py status     # iptables -L -n -v
python3 08-verify-policy.py           # 12-flow verification
```

**SDNC AI Agent integration target:** thay thế `07-apply-policy.py` bằng REST/NETCONF call từ ONAP SDNC.

---

## 6. Traffic Tap — IDS as Passive Mirror (SPAN)

> **Update 2026-05-21 — verified trực tiếp trên lab đang chạy (GNS3 API + console + eve.json).**
> Cơ chế capture thực tế là **passive port-mirror (`tc clsact` + `mirred`) trên LEAF → IDS**, KHÔNG phải L3 in-path routing.
> Các bản ghi cũ ("Suricata = L3 next-hop", "static route via Suricata", "Update 2026-05-12 in-path") là **SAI** — đã đính chính bên dưới. Suricata là **passive IDS**: `ip_forward=0`, không có route tới lab subnet, không nằm trên data path.

### 6.1 Cơ chế thực tế — passive mirror tới IDS

East-west traffic đi đường bình thường `host → LEAF → SPINE → LEAF → host`. Mỗi LEAF **mirror một bản copy** traffic ra cổng `eth4` nối thẳng vào IDS. IDS chỉ nghe (promiscuous), không forward, không can thiệp luồng.

```
   WEB / DB hosts                                      APP / MGT hosts
        │                                                   │
 ┌──────┴────────────┐        eth0 (uplink)        ┌────────┴──────────┐
 │   SONIC-LEAF-1     │────────── ↕ SPINE ──────────│   SONIC-LEAF-2     │
 │ tc clsact+mirred:  │                             │ tc clsact+mirred:  │
 │ eth0,eth2,eth3→eth4│                             │ eth0,eth2,eth3→eth4│
 └─────────┬──────────┘                             └─────────┬──────────┘
      eth4 │ (mirror copy)                               eth4 │ (mirror copy)
           ▼                                                  ▼
       IDS:eth0 ──────────► af-packet (promisc) ◄─────── IDS:eth1
                                   │
                          eve.json (alert + flow)
```

**Wiring (verify qua GNS3 API + console):**

| Link | Vai trò |
|------|---------|
| LEAF-1:eth4 (Ethernet16) ↔ IDS:eth0 | mirror zone WEB+DB + uplink LEAF-1 |
| LEAF-2:eth4 (Ethernet16) ↔ IDS:eth1 | mirror zone APP+MGT + uplink LEAF-2 |
| IDS:eth2 ↔ NAT | management + REST API `:8765` |

**Cấu hình mirror thật trên mỗi LEAF (verify `tc filter show`):**
```bash
# clsact qdisc + mirred egress-mirror trên các NIC vật lý, copy ra eth4 (cổng tới IDS)
tc qdisc  add dev eth0 clsact                                   # eth0 = uplink SPINE
tc filter add dev eth0 ... action mirred egress mirror dev eth4
# lặp lại cho eth2 (host link A) và eth3 (host link B)
```
- LEAF-1 mirror: `eth0` (uplink SPINE) + `eth2` (WEB) + `eth3` (DB) → `eth4` → IDS:eth0
- LEAF-2 mirror: `eth0` (uplink SPINE) + `eth2` (APP) + `eth3` (MGT) → `eth4` → IDS:eth1
- IDS `eth0`/`eth1`: `promisc on`, **không IP** (chỉ capture). `eth4` trên LEAF **không thuộc Bridge** (đúng kiểu SPAN destination).
- Vì mirror **bao gồm cả uplink SPINE (eth0)** nên IDS thấy được cả hai chiều của inter-leaf traffic.
- Đây là bản phần-mềm tương đương **SONiC Everflow / ERSPAN** trên SONiC-VS (không có ASIC).

**Bằng chứng KHÔNG phải L3 in-path (verify 2026-05-21):**
- Trên IDS: `cat /proc/sys/net/ipv4/ip_forward` = **0**; `ip route` **không** có route nào tới `10.1/16`, `10.2/16` → IDS không thể route/forward.
- Trên LEAF-2: `ip route get 10.1.200.10` → **via 10.0.2.1 dev eth0 (SPINE)**, không qua IDS. Không tồn tại static route "via Suricata".
- `show mirror_session` rỗng, không OVS → mirror làm ở tầng **Linux `tc` trên NIC**, không phải SONiC SPAN config.

> **Lịch sử thiết kế (vì sao tài liệu từng mâu thuẫn):**
> - **v1** — GNS3 Ethernet-Hub TAP chèn trên link SPINE↔LEAF ([09-deploy-ids.py](dc-fabric-setup/09-deploy-ids.py)).
> - **v2** — direct LEAF↔IDS + `tc mirred` ([12-refactor-ids-direct.py](dc-fabric-setup/12-refactor-ids-direct.py), [13-fix-ids-full.py](dc-fabric-setup/13-fix-ids-full.py)).
>
> Bản chạy hiện tại là **v2**; live config đặt mirror trên **NIC vật lý** (`eth0/eth2/eth3`) qua `clsact` (script đời đầu viết trên Vlan SVI — đã đổi). Mọi mô tả "Suricata = L3 in-path next-hop" trong doc cũ là sai.

### 6.2 Hệ quả — Asymmetric capture (do mirror, KHÔNG phải routing)

Suricata capture trên 2 NIC với `cluster_flow` (cluster-id 98/99). Một flow east-west đôi khi bị tách: trong một flow-record chỉ thấy 1 chiều (vd `WEB→APP:8080` có `pkts_toclient=0`, state `new`).

- Đây **KHÔNG** phải "reply route qua SPINE bypass Suricata" — Suricata không in-path nên không có gì để "bypass"; hơn nữa mirror đã gồm uplink SPINE nên chiều reply inter-leaf vẫn được copy. Thực tế nhiều flow thấy đủ 2 chiều (`state=closed`, vd APP↔DB, ssh).
- Nguyên nhân flow 1 chiều là **artifact của `cluster_flow`** (hash 2 chiều lên 2 cluster khác nhau) cộng mirror per-interface — không phải Suricata bị mù chiều reply.

→ Với phần flow chỉ thấy 1 chiều, TCP stream reassembly có thể stuck `NEW`. Workaround Suricata stream config (`midstream`, `async-oneside`) xem §7.1; pattern rule dùng `flags:S` + `flow:to_server` (bắt theo chiều khởi tạo) để robust.

---

## 6A. DCN Service Simulation — Realistic East-West Workload

Để IDS có gì observe (không chỉ test với hping3), 4 Alpine hosts được provision với services + cron-driven traffic generator mô phỏng workload thực tế của một DCN.

### 6A.1 Service inventory per zone

| Zone | Host | Service | Port | Implementation | Listener pattern |
|------|------|---------|------|----------------|------------------|
| WEB | Alpine-1 (10.1.100.10) | banner HTTP | 80 | busybox `nc -l -p 80 < /tmp/banner.html` loop | request-then-reply (file redirect, không pipe) |
| WEB | Alpine-1 | sshd | 22 | OpenSSH (`PermitRootLogin yes`, `PermitEmptyPasswords yes`) | persistent |
| DB | Alpine-2 (10.1.200.10) | pg-mock SQL-aware | 5432 | busybox `nc -lk -e /usr/local/bin/pg-mock.sh` | connection-per-message, returns SQL-shape based on payload prefix |
| DB | Alpine-2 | sshd | 22 | OpenSSH | persistent |
| APP | Alpine-3 (10.2.100.10) | banner HTTP | 8080 | busybox `nc -l -p 8080 < banner` | request-then-reply |
| APP | Alpine-3 | sshd | 22 | OpenSSH | persistent |
| MGT | Alpine-5 (10.2.50.10) | sshd | 22 | OpenSSH | persistent (no app — control-only zone) |

> **busybox 1.37 nc gotcha:** `nc -lk -e` works **chỉ khi handler emits 1 line then exits**; multi-line responses cần pattern `pre-render to file → nc -l -p PORT < file`. Discovery cost: nửa ngày debug, lessons-learned đã track trong memory.

### 6A.2 Cron-driven traffic generators

Tất cả crons trong `/etc/crontabs/root`, started bằng `crond -f -L /var/log/dcn/crond.log`:

| Cron | Source | Direction | Cadence | Purpose |
|------|--------|-----------|---------|---------|
| `shopper` | WEB → APP:8080 | east-west, allowed | 30s | Mô phỏng web tier proxy → app tier |
| `noise` | APP → DB:5432 | east-west, allowed | 30s | 4 SQL shapes (SELECT users, SELECT orders, INSERT log, UPDATE session) |
| `mgt-scrape` | MGT → WEB:80 / APP:8080 / DB:5432 | inbound to all zones (audit-by-design) | 60s | banner + service-health probe |
| `mgt-audit` | MGT → WEB:22 / APP:22 / DB:22 (rotating) | SSH | 2 min | Compliance SSH login + `uptime` capture |
| `mgt-logpull` | MGT → APP:22 | SSH | 5 min | `tail -100 /var/log/dcn/*.log` over SSH |
| `attacker-web` | WEB → DB:5432 | violation (P1) | dormant — armed by scenario | Injected only during demo |
| `attacker-db` | DB → 8.8.8.8 / external | violation (P1) | dormant | Simulated C2 callback |

**Kết quả continuous:** ~120 flows/min baseline, ~11 P4 audit alerts/min từ SID 9000020 (by design — MGT outbound = always alerted), 0 P1/P2 alerts trừ khi scenario chạy.

### 6A.3 Bootstrap pipeline — provision 4 hosts

| File | Target | LOC | Notes |
|------|--------|-----|-------|
| `/3s-com/dataplane/bootstrap/web-host.sh` | Alpine-1 | 135 | banner :80 + sshd + shopper cron + dormant attacker |
| `/3s-com/dataplane/bootstrap/db-host.sh`  | Alpine-2 | 119 | pg-mock SQL-aware + sshd + dormant attacker |
| `/3s-com/dataplane/bootstrap/app-host.sh` | Alpine-3 | 123 | banner :8080 + sshd + noise→DB cron |
| `/3s-com/dataplane/bootstrap/mgt-host.sh` | Alpine-5 | 133 | sshd + audit/scrape/logpull crons + scenario controllers |

**Push mechanism:** `/tmp/paste_bootstrap.py` — base64-encode script, paste qua GNS3 console proxy port (5008/5011/5014/5016), `base64 -d > /root/bootstrap.sh && sh /root/bootstrap.sh`. Idempotent: re-run sẽ overwrite cleanly.

### 6A.4 Compromise / restore scenarios (MGT-driven demo)

Scenario controllers ở `/root/scenario/` trên Alpine-5 (MGT). Mỗi scenario có 3 scripts (compromise/restore/status), trigger từ console hoặc qua AI agent's run.sh.

| Script | Effect | Detection |
|--------|--------|-----------|
| `compromise-web.sh` | SSH→WEB, write `/usr/local/bin/attacker-web-loop.sh`, nohup loop `nc -z -w2 10.1.200.10 5432; sleep 15` | SID 9000001 P1 (~10s/alert) |
| `compromise-db.sh`  | SSH→DB, write `/usr/local/bin/attacker-db-loop.sh`, nohup loop `nc -z -w2 8.8.8.8 443; sleep 15` | SID 9000002 P1 (~10s/alert) |
| `restore-web.sh` / `restore-db.sh` | SSH, kill PID từ `/tmp/attacker-{web,db}.pid`, rm loop script | alert stream goes quiet |
| `status-web.sh` / `status-db.sh`   | check `/tmp/scenario-{web,db}.state` → `armed (since TS)` hoặc `disarmed` | — |

**State files:** `/tmp/scenario-{web,db}.state` trên MGT (chứa ISO timestamp khi arm). Idempotent: gọi compromise khi đã armed → no-op + thông báo. Gọi restore khi đã restored → no-op.

> **Pitfall — `pkill -f` self-kill:** SSH command line containing substring `attacker-{web,db}-loop` sẽ bị `pkill -f attacker-{web,db}-loop` matched ngay chính cmdline của SSH session, gây SIGTERM lên parent shell → SSH exit 255. **Fix:** kill bằng PID file (`kill -9 $(cat /tmp/attacker-web.pid)`), không dùng pattern match.

**Demo flow:** start clean → (P4 audit baseline only) → `compromise-web.sh` → SID 9000001 visible < 30s → `restore-web.sh` → quiet.

### 6A.4.1 Validation 2026-05-04 (rewritten scripts)

| Step | Result |
|------|--------|
| 6 scripts pushed via console 5016 (base64 paste) | ✅ |
| `compromise-web` armed → 50s sau, SID 9000001 delta = +8 | ✅ ~10s/alert |
| `restore-web` → status returns `disarmed`, alerts dừng | ✅ |
| `compromise-db` armed → 50s sau, SID 9000002 delta = +8 | ✅ ~10s/alert |
| `restore-db` → cleanup OK | ✅ |
| `/alerts/clear` returns `{cleared_at: ISO}` (since-based) | ✅ working |
| `/alerts?since=<cleared_at>` returns count=0 ngay sau clear | ✅ |

### 6A.5 Validation checkpoint (2026-05-03)

| Test | Result |
|------|--------|
| 4 zones up, services healthy | ✅ |
| Continuous east-west traffic (cron-driven) | ✅ 120 flow/min |
| SC compromise-web → SID 9000001 fires | ✅ < 30s |
| SC compromise-db → SID 9000002 fires | ✅ < 30s |
| Baseline FPR (P1+P2 false positives over 1h) | **0%** |
| MGT audit baseline (SID 9000020) | ✅ ~11/min by design |

---

## 7. Detection Rules — Suricata 8.0

**Source bundle (current):** `zma/suricata/ids-vm/rules/zt-lab.rules` + `zma/suricata/ids-vm/suricata-zt.yaml` — `cp` vào IDS VM `/etc/suricata/...` (xem §7A.2 deploy steps).
**Path inside VM:** `/etc/suricata/rules/zt-lab.rules` + `/etc/suricata/suricata-zt.yaml`.
**Capture:** `af-packet` cluster_flow trên `eth0` (mirror từ LEAF-1) + `eth1` (mirror từ LEAF-2)
**eve.json types:** `alert`, `flow` (flow logging bật để dashboard show normal traffic)
**Reload:** ⚠️ `kill -USR2` KHÔNG reload trên build này (yaml thiếu `detect-engine: rule-reload`, verify 2026-05-21) → nạp rule mới phải `rc-service suricata-zt restart`

### 7.1 Asymmetric capture workaround (Suricata stream config)

> **Lưu ý lịch sử:** Bảng eval bên dưới (2026-05-12) tham chiếu SID 9000030–9000035 thuộc bộ rule CŨ — đã thay bằng Yatesbury 9000040–9000052 (§7.2; SID cũ chỉ còn trong git history). Phần giải thích "reply DB→APP đi qua SPINE bypass Suricata" cũng đã được **đính chính**: capture là passive mirror, asymmetric là do mirror per-interface + `cluster_flow`, KHÔNG phải routing bypass (§6.2). Phần stream config (`midstream`/`async-oneside`) vẫn đúng và đang dùng.

**Vấn đề:** Capture asymmetric (§6.2) — do mirror per-interface + `cluster_flow` tách 2 chiều, một số flow-record chỉ thấy forward direction (request), không thấy reply. Mặc định Suricata không reassemble TCP stream nếu không thấy 3-way handshake + ACK → các rule có `flow:established` và `content:` match không trigger được.

**Workaround (2026-05-12) — bật trong `suricata-zt.yaml`:**
```yaml
stream:
  midstream: true            # treat flow as established without seeing SYN handshake
  midstream-policy: pass-flow # explicit accept mid-stream session
  async-oneside: true        # inspect segments without waiting for ACK from opposite direction
```

**Tác động đo được (eval 2026-05-12, runs trước/sau khi bật):**

| SID | Rule pattern | Trước (midstream off) | Sau (midstream + async-oneside) |
|---|---|---|---|
| 9000031 | `flags:S` threshold | 10/10 PASS | 10/10 PASS |
| 9000033 | `flow:established, content:"DROP TABLE"` | **0/10 FAIL** | **10/10 PASS** |
| 9000035 | `flags:S` cross-tier | 10/10 PASS | 10/10 PASS |
| 9000032 | `flow:established,from_server dsize>4096` (DB→APP) | 0/10 FAIL | **0/10 FAIL (deferred — see below)** |

**SID 9000032 đã dropped khỏi production test suite (2026-05-13)** — stream config không cứu được vì reply DB→APP đi qua SPINE bypass Suricata hoàn toàn (§6.2). Đây là routing-level limitation, không phải config-level. Để revival sẽ cần SONIC LEAF-1 add static route `10.2.0.0/16 via Suricata` (đối xứng với LEAF-2). Rule trên IDS VM giữ nguyên (zero fire, không tốn resource); eval script `eval_app_db_bulk.py` giữ trong repo cho future revival. Xem [EXPERIMENT.md §6.9.3](EXPERIMENT.md#693--deferred-scenario--sid-9000032-dbapp-bulk-reply).

**Pattern thiết kế rule sau workaround:**
- `flags:S` cho rate/threshold detection (forward-only đủ).
- `flow:established,to_server` + `content` cho semantic detection chiều request — work với async-oneside.
- `flow:established,from_server` (reply-side detection) — **tránh** nếu routing asymmetric không qua Suricata.

### 7.2 Active rule set — 21 SIDs (verified live 2026-05-21)

File `/etc/suricata/rules/zt-lab.rules` đang chạy **21 rule** (`21 rules successfully loaded, 0 failed`): 8 rule ZT gốc (CATEGORY 1–4) + 13 rule **Yatesbury benchmark** (NetVigil NSDI'24, CATEGORY 5–9). Tất cả **signal-only** (mô tả cái quan sát được; Intelligence Layer/agent đọc KG để quyết định hành động). Quy ước: `internal` = `[10.1.0.0/16,10.2.0.0/16]`; zone WEB=10.1.100/24, DB=10.1.200/24, APP=10.2.100/24, MGT=10.2.50/24. Priority lấy từ keyword `priority:` trong rule (ghi đè classtype).

**CATEGORY 1 — Policy violations (critical)**
| SID | Prio | Match (rev) | Msg |
|---|---|---|---|
| 9000001 | P1 | `WEB→DB:[5432,3306,1433,27017]` flags:S (rev3) | WEB direct to DB - microsegmentation bypass |
| 9000002 | P1 | `DB→!internal any` flags:S (rev4) | DB initiating outbound connection |

**CATEGORY 2 — Lateral movement**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000003 | P2 | `APP→WEB:[80,443,22]` flags:S | APP reverse call to WEB - lateral movement |
| 9000004 | P2 | `WEB→MGT:[22,3389]` flags:S | WEB to MGT - unauthorized access |
| 9000005 | P2 | `APP→MGT:[22,3389]` flags:S | APP to MGT - unauthorized access |

**CATEGORY 3 — Reconnaissance**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000010 | P3 | ICMP echo, threshold 3/10s by_src | ICMP ping sweep detected |
| 9000011 | P3 | `internal→internal ![22,5432,8080]` flags:S, 15/10s by_src (rev2) | Possible port scan |

**CATEGORY 4 — Audit**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000020 | P4 | `MGT→any` (ip), limit 1/60s by_src | Management zone access |

**CATEGORY 5 — Scanning (Yatesbury)**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000040 | P3 | `internal→internal ![22,5432,8080]` flags:S, 20/30s by_src (rev2) | Vertical port scan — many ports same dst |
| 9000041 | P3 | `internal→internal [23,80,443,3389,3306,1433,8443]` flags:S, 5/60s by_src (rev2) | TCP probe on key service ports |
| 9000042 | P3 | `udp internal→internal`, 15/60s by_src | UDP probe on many ports |

**CATEGORY 6 — Flooding (Yatesbury)**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000043 | P2 | `tcp any→internal` flags:S, 200/10s by_src | TCP SYN flood (single source) |
| 9000044 | P2 | `tcp any→internal` flags:S, 50/10s by_both | TCP SYN contribution (DDoS per-src) |
| 9000045 | P2 | `udp any→internal`, 500/10s by_dst | UDP packet flood to destination |

**CATEGORY 7 — Command & Control / tunneling (Yatesbury)**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000046 | P2 | `tcp internal→!internal` flags:S dsize<200, 3/90s by_src (rev2) | Periodic small outbound — C2 heartbeat |
| 9000047 | P2 | `udp any:53→internal` dsize>1000, 5/30s by_dst | DNS response abnormally large (amplification) |

**CATEGORY 8 — Application-layer DB content (Yatesbury)**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000048 | P1 | `tcp any→DB:[5432,3306,1433]` content "UNION SELECT" nocase | SQL syntax — UNION SELECT |
| 9000049 | P1 | `tcp any→DB:[5432,3306,1433]` content "OR 1=1" nocase | SQL syntax — tautology |
| 9000050 | P1 | `tcp any→DB:[5432,3306,1433]` pcre DROP TABLE/TRUNCATE/DELETE FROM | Destructive SQL statement |
| 9000051 | P1 | `tcp !{APP,DB}→DB:[5432,3306,1433,27017]` flags:S | DB connection from non-APP zone |

**CATEGORY 9 — Multi-stage exploit recon (Yatesbury Infection Monkey)**
| SID | Prio | Match | Msg |
|---|---|---|---|
| 9000052 | P3 | `internal→internal [23,135,139,445,3389,8443]` flags:S, 10/60s by_src (rev2) | Probe on commonly-exploited service port |

> **Đính chính so với bản cũ:** Doc trước mô tả "11 SID Class A–D" với 9000030–9000035 và nói đã xóa 9000003/4/5 — KHÔNG đúng với set hiện tại. Set đang chạy GIỮ 9000003/4/5 (lateral) và thay Class D bằng bộ Yatesbury 9000040–9000052. SID 9000030–9000035 chỉ còn trong git history.
> **FP fix 2026-05-21:** 9000011 / 9000040 / 9000041 / 9000052 nâng **rev2** — scope `internal→internal` + loại baseline port 22/5432/8080 khỏi watch-list → hết false-positive trên traffic hợp lệ (WEB→APP:8080, APP→DB:5432, MGT→:22). Scan thật vẫn fire (verify bằng nmap APP→DB).

### 7.3 Output mode — alert + flow (current state, verified 2026-05-21)

> **Đính chính:** Doc trước ghi "pure flow-log mode (2026-05-14): rules stub, Suricata không fire SID, chỉ flow/netflow/dns/http". KHÔNG còn đúng. Hiện **rules ACTIVE (21 SID, §7.2)**, Suricata phát **`alert` + `flow`**. Startup log: `21 rules successfully loaded, 0 rules failed`.

Intelligence Layer dùng **cả hai**: `alert` (đã phân loại theo SID) qua SSE realtime, và `flow` (đặc trưng kiểu NetVigil) qua poller — agent reason trên KG (threat-patterns + severity-scoring + flow-features).

#### 7.3.1 (lịch sử) Flow-log-only mode

Giai đoạn 2026-05-14 từng chạy flow-only để so khớp NetVigil NSDI'24 (rules thay bằng stub → Suricata log `0 signatures processed`, là **bình thường** không phải lỗi). Đã kết thúc; rules đầy đủ đang active. Có thể bật lại bằng cách stub lại rules file nếu cần eval flow-only.

#### 7.3.2 Suricata yaml outputs (suricata-zt.yaml) — thực tế đang chạy

```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert      # 21 SID active (§7.2) → có alert thật
        - flow       # NetVigil-style features cho agent
stream:
  midstream: true                # treat asymmetric capture as established
  midstream-policy: pass-flow
  async-oneside: true            # inspect segments without ACK from opposite side
```
> Output chỉ gồm **`alert` + `flow`** (KHÔNG có `netflow`/`dns`/`http` — bản doc cũ ghi sai).

#### 7.3.3 Verification post-deploy

```sh
# event_type distribution — phải thấy CẢ alert VÀ flow
tail -200 /var/log/suricata/eve.json | python3 -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try: c[json.loads(line).get('event_type')] += 1
    except: pass
print(c)
"
# Expect: Counter({'flow': N, 'alert': M})
# Startup: 'detect: 1 rule files processed. 21 rules successfully loaded, 0 rules failed'
```

#### 7.3.4 Yatesbury compromise scripts (8 new scenarios)

Spec: [`experiments/DATAPLANE_YATESBURY_SPEC.md`](../experiments/DATAPLANE_YATESBURY_SPEC.md)

Each scenario requires a `compromise-<key>.sh` + `restore-*.sh` pair on
the appropriate Alpine host:

| Scenario | Host | Tools needed |
|---|---|---|
| Vertical port scan | APP | nmap |
| SYN flood DoS | APP | hping3 |
| SYN flood DDoS | APP + WEB | hping3 (coordinated) |
| UDP DDoS | APP + WEB | hping3 -2 |
| Distributed scan | APP + WEB | nmap (low-and-slow) |
| Infection Monkey | APP | nmap + nc + ssh |
| C&C beacon | APP | curl (periodic outbound to NAT2) |
| Unauthorized DB access | WEB | psql client |

Bootstrap dependencies for Alpine hosts:
```sh
apk add --no-cache hping3 nmap nmap-scripts netcat-openbsd curl postgresql-client
```

Trigger pattern unchanged (touch flag file → cron picks up → run attack →
auto-restore after 60-90s).

#### 7.3.5 Reboot recovery

After dataplane VM reboot, redeploy bundle (Alpine ISO tmpfs has no persistence):

```sh
# On gns3vm host
sshpass -p <pwd> ssh dis@10.10.6.238
# Or for IDS VM:
ssh root@192.168.122.205   # if SSH up post-reboot
cd /tmp/ids-vm
sh ./redeploy.sh           # apk add python3 + install + rc-update + start
```

Verify after redeploy:
```sh
rc-service suricata-zt status && rc-service ids-api status
curl -s http://192.168.122.205:8765/health
```

---

## 7A. IDS-Suricata VM — Deploy & Architecture

> Bundle source: `zma/suricata/ids-vm/` — sync xuống VM khi reboot/redeploy. Alpine ISO boot tmpfs ⇒ KHÔNG persistence, mọi reboot phải redeploy từ bundle.
> Deploy confirmed 2026-05-08 — memory leak fix live (RSS ~33MB constant, vs ~1.65GB OOM ~3h trước fix); cả `ids-api` và `suricata-zt` đều supervised qua OpenRC.

### 7A.1 Bundle layout

```
zma/suricata/ids-vm/
├── ids-api.py             # REST + SSE server (232 LOC, stdlib only) — md5 b7fc60a2
├── ids-api.openrc         # OpenRC service (supervise-daemon, respawn 3s)
├── suricata.openrc        # OpenRC service cho suricata-zt (supervise-daemon, respawn 5s)
├── suricata-zt.yaml       # Suricata config (af-packet eth0+eth1, eve.json types: alert+flow, rotate 86400s)
├── redeploy.sh            # One-shot post-reboot installer (apk add python3 + install + rc-update + start)
└── rules/
    └── zt-lab.rules       # 21 rules: 8 ZT gốc + 13 Yatesbury (SID 9000001-9000052) — xem §7.2
```

### 7A.2 Deploy commands (chạy trên IDS VM sau reboot)

```bash
# Telnet console: 112.137.129.232:5018  | login: root (no password)
# scp bundle vào VM (vd qua libvirt 192.168.122.205) rồi:
cd /path/to/ids-vm/
sh ./redeploy.sh
```

`redeploy.sh` lo trọn gói: `apk add python3` (Alpine ISO không có sẵn) → `install` files → `rc-update add` cả hai service → `rc-service start` Suricata trước rồi ids-api → verify port 8765 listening.

Manual deploy (nếu cần kiểm soát từng bước):
```bash
apk add --no-cache python3
install -m 755 ids-api.py            /usr/local/bin/ids-api.py
install -m 755 ids-api.openrc        /etc/init.d/ids-api
install -m 755 suricata.openrc       /etc/init.d/suricata-zt
install -m 644 suricata-zt.yaml      /etc/suricata/suricata-zt.yaml
install -m 644 rules/zt-lab.rules    /etc/suricata/rules/zt-lab.rules
mkdir -p /var/log/suricata
rc-update add suricata-zt default && rc-service suricata-zt start
rc-update add ids-api     default && rc-service ids-api     start
```

Verify sau khi deploy:
```bash
curl -s http://10.10.6.238:8765/health    # {status:ok, suricata:true, ring_alerts, ring_flows, sse_clients, uptime_sec}
curl -s http://10.10.6.238:8765/service-health    # 4/4 services up
ps -p $(pgrep -f ids-api.py) -o rss,vsz,etime    # RSS phải ổn định ~33MB
```

### 7A.3 ids-api.py — Architecture (memory-bounded, real-time)

Single Python process, `ThreadingHTTPServer`. 1 background tail thread + N HTTP handler threads.

```
┌─────────────────────────────────────────────────────────────┐
│ ids-api.py (port :8765)                                     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ tail_loop (daemon thread)                            │  │
│  │   - readline() từ /var/log/suricata/eve.json         │  │
│  │   - manual byte-offset (pos += len(line))            │  │
│  │   - parse JSON, filter event_type ∈ {alert, flow}    │  │
│  │   - alert: append ring + broadcast tới SSE subs      │  │
│  │   - flow:  append ring (KHÔNG broadcast)             │  │
│  │   - watch st_ino → reopen + reset pos khi rotate     │  │
│  └──────────────────────────────────────────────────────┘  │
│                       │                                     │
│                       ▼                                     │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Ring buffers (lock-protected)                        │  │
│  │   _alerts:      deque(maxlen=2000)  ~1 MB           │  │
│  │   _flows :      deque(maxlen=2000)  ~1 MB           │  │
│  │   _sse_clients: list[Queue(maxsize=256)] cap 8      │  │
│  └──────────────────────────────────────────────────────┘  │
│        ▲                  ▲                ▲                │
│  ┌─────┴──┐         ┌─────┴───┐      ┌────┴──────────┐    │
│  │ /alerts│         │ /flows  │      │ /stream SSE   │    │
│  │ /health│         │ /service│      │ try/finally   │    │
│  │ slice  │         │ -health │      │ remove client │    │
│  │ ring   │         │ infer   │      │               │    │
│  └────────┘         └─────────┘      └───────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Memory ceiling: ~33MB RSS constant** — không phụ thuộc eve.json size, request rate, hay SSE client count.

**Real-time latency:** alert ghi vào eve.json → SSE push tới subscriber **< 500ms worst case** (TAIL_POLL_SEC=0.5s sleep window), trung bình ~250ms.

### 7A.4 Suricata config (suricata-zt.yaml — key fields)

| Field | Value | Note |
|-------|-------|------|
| Capture interfaces | `af-packet eth1` (cluster-id 99) + `eth0` (cluster-id 98) | passive `tc mirred` SPAN từ LEAF (§6.1), KHÔNG phải L3 in-path |
| `HOME_NET` | `[10.1.0.0/16, 10.2.0.0/16]` | Toàn bộ lab subnet |
| `stream.midstream` | `true` | (2026-05-12) Treat flow established without 3-way handshake — routing asymmetric (§6.2) |
| `stream.midstream-policy` | `pass-flow` | Explicit accept mid-stream session |
| `stream.async-oneside` | `true` | Inspect segments without waiting ACK from opposite direction — bắt buộc cho content rules với asymmetric routing |
| eve.json output | `types: [alert, flow]` | Flow logging bật cho dashboard / `/service-health` |
| Profile | `low`, `max-pending-packets: 512` | VM resource-constrained |
| Rules path | `/etc/suricata/rules/zt-lab.rules` | ⚠️ `kill -USR2` là NO-OP (thiếu `detect-engine: rule-reload`); nạp rule mới → `rc-service suricata-zt restart` |
| eve.json rotate | `rotate-interval: 86400` (cả `eve-log` và `fast`) | Suricata 8 yêu cầu integer giây — KHÔNG nhận string `daily` |

### 7A.5 OpenRC services

**ids-api.openrc** (`/etc/init.d/ids-api` — pidfile `/run/ids-api.pid`):
```
supervisor       = supervise-daemon
command          = /usr/bin/python3 /usr/local/bin/ids-api.py
respawn_delay    = 3
respawn_max      = 0       # vô hạn
respawn_period   = 60
output_log       = /var/log/ids-api.log
```

**suricata.openrc** (`/etc/init.d/suricata-zt` — pidfile `/run/suricata-zt.pid`):
```
supervisor       = supervise-daemon
command          = /usr/bin/suricata
command_args     = -c /etc/suricata/suricata-zt.yaml --af-packet
respawn_delay    = 5
respawn_max      = 0       # vô hạn
respawn_period   = 60
```

### 7A.6 Operational notes

| Topic | Hiện tại | Status |
|-------|----------|--------|
| ids-api auto-respawn | OpenRC supervise-daemon, 3s delay | ✓ stable |
| Suricata auto-respawn | OpenRC supervise-daemon (`suricata.openrc`), 5s delay, foreground af-packet | ✓ live 2026-05-08 |
| eve.json rotate | `rotate-interval: 86400` (eve-log + fast) — daily roll | ✓ live 2026-05-08 |
| Logrotate copytruncate | Inode change OR `st.st_size < pos` (truncate-in-place) | ✓ live ([ids-api.py](../zma/suricata/ids-vm/ids-api.py#L49)) |
| Post-reboot recovery | `redeploy.sh` one-shot installer (Alpine tmpfs ⇒ phải redeploy mỗi reboot) | ✓ bundle |
| SSE slow client | Queue full → kick client | ✓ by design — server không bị slow client kéo xuống; ids-agent auto-reconnect |
| SSE client cap | 8 clients max → 503 nếu vượt | Đủ cho ids-agent + 2-3 dev tab |

### 7A.7 Memory leak fix history (2026-05-06)

**Symptom trước fix:** RSS phình từ ~50MB → 1.65GB sau ~3h, OOM kill, supervise-daemon respawn loop. ids-agent SSE rớt → fallback polling 2s permanent.

**Root cause:** `read_alerts()` cũ mở `eve.json` (102MB / 172k dòng) và load TOÀN BỘ vào list mỗi request:
```python
for line in f: alerts.append(json.loads(line))   # 100MB/request
return alerts[-last:]
```
ThreadingHTTPServer × N concurrent → N × 100MB allocated cùng lúc → OOM.

**Fix (deploy 2026-05-06, current md5 b7fc60a2 — bao gồm copytruncate fix 2026-05-08):**
- Background tail thread: `readline()` line-by-line, append vào `deque(maxlen=2000)` mỗi loại
- HTTP handlers slice từ ring (O(N), không I/O)
- SSE: per-client `Queue(maxsize=256)`, cap 8 clients, `try/finally` cleanup
- Logrotate: watch `st.st_ino`, auto-reopen
- BrokenPipe: `_safe_write` / `_safe_flush` bao quanh mọi `wfile` ops

**Bug edge case bắt được lúc deploy:** Python text-mode `for line in f` cấm gọi `f.tell()` mid-iteration (`OSError: telling position disabled by next() call`). Đổi sang `readline()` + manual offset (`pos += len(line)`).

**Acceptance test pass:**
- Bootstrap 177.5k dòng eve.json → ring đầy 2000 trong 9s
- 20 concurrent `/alerts?last=100`: tất cả 200, latency ≤ 230ms
- 4/4 services báo up qua `/service-health`
- SID 9000020 alert real-time qua SSE confirmed
- RSS 33MB constant under wrk stress

---

## 8. North-bound API — for ONAP SDNC Integration

### 8.1 IDS Alert API (Suricata side)

Base URL: `http://10.10.6.238:8765` (LAN) / `http://112.137.129.232:8765` (public NAT)
**Source:** `/usr/local/bin/ids-api.py` trong IDS-Suricata VM (xem §7A cho deploy + architecture).
**Exposure:** libvirt `virbr0` NAT bridge → DNAT từ host `:8765` → VM `192.168.122.205:8765`.

| Method | Path | Response |
|--------|------|----------|
| GET | `/health` | `{status, suricata: bool, ring_alerts, ring_flows, sse_clients, uptime_sec, ts}` |
| GET | `/alerts?last=N&since=ts` | `{count, summary{sid:n}, alerts[]}` — slice từ ring (cap 2000) |
| GET | `/alerts/clear` | `{cleared_at: ts}` — client dùng làm anchor cho `?since=` để skip pre-F5 alerts |
| GET | `/flows?last=N&since=ts` | `[flow event objects]` — slice từ ring, cap 500 mỗi request |
| GET | `/stream` | SSE — alert events only (flow KHÔNG broadcast); heartbeat `: hb` mỗi 15s; cap 8 clients (503 nếu vượt) |
| GET | `/service-health` | Passive flow-inference từ ring 180s gần nhất: `{services:[{name,ip,port,zone,status:up\|unknown}], method:"flow-inference-ring"}` |

### 8.2 Go IDS Agent (real-time bridge + enforcement proxy)

Base URL: `http://10.10.6.238:8766` (LAN runs trên control-plane host); container `ids-agent` trong [docker-compose.yml](../docker-compose.yml).

> After refactor (2026-04-xx): pure proxy/bridge. `tryAutoBlock()` removed. Auto-enforcement is now handled by Intelligence Layer.

**SSE upstream resilience (2026-05-06):**
- Watchdog cancels SSE connection nếu không nhận được line nào (data hoặc `: hb` heartbeat) trong `sseStallTimeout = 30s`. Suricata gửi heartbeat mỗi 15s → 30s = 2 missed heartbeats → force reconnect.
- Exponential backoff giữa retries: 1s → 2s → 4s → 8s → 16s → 30s capped.
- **Bỏ permanent polling fallback** — luôn retry SSE. Cũ: 5 SSE fails liên tiếp → switch sang polling mode VĨNH VIỄN, không upgrade lại; gây bug "Monitor stuck dù Suricata UP". Mới: chỉ có 1 mode (SSE), retry forever.
- File: [ids-agent/main.go](../ids-agent/main.go) — `consumeSSE()` + `runBridge()`.

| Method | Path | Use |
|--------|------|-----|
| GET | `/health` | Proxy → Suricata `/health` |
| GET | `/alerts` | Proxy → Suricata `/alerts` |
| GET | `/flows` | Proxy → Suricata `/flows` (FE Monitor flow poller) |
| GET | `/events` | SSE — alerts + heartbeat (15s) + `{type:"connected"}` event |
| GET | `/ws` | WebSocket — same payload as `/events` |
| GET | `/rules` | Proxy → SF `GET /api/rules` (gNMI format: `{leaves:{leaf-N:{rules:{notification:[{update:[{path,val}]}]}}}}`) |
| **POST** | **`/rules`** | **Push rule to SF; force `source=agent` server-side — Intelligence Layer primary path** |
| **DELETE** | **`/rules/{rule_id}`** | **Revoke rule from SF + LEAF — Intelligence Layer TTL cleanup** |
| POST | `/autoblock` | Frontend manual block by IP |
| DELETE | `/autoblock/unblock/{id}` | Frontend manual unblock |

**Note on gNMI response format:** `GET /rules` returns the raw gNMI notification structure. Rule fields use YANG names: `src-prefix` (not `src_ip`), `rule-id` (not `rule_id`), `src-port`/`dst-port`. Clients must parse accordingly.

### 8.3 Alert JSON Schema

```json
{
  "timestamp": "2026-04-19T18:13:01Z",
  "event_type": "alert",
  "src_ip": "10.1.100.10",
  "dest_ip": "10.1.200.10",
  "proto": "TCP",
  "alert": {
    "signature": "[ZT-VIOLATION] WEB direct to DB - microsegmentation bypass",
    "signature_id": 9000001,
    "severity": 1,
    "category": "policy-violation"
  }
}
```

---

## 9. Control Plane Integration — What SDNC Needs to Do

### 9.1 Connector Targets

ONAP SDNC AI Agent cần build connector tới:

| Target | Protocol | Endpoint | Action |
|--------|----------|----------|--------|
| SONIC-SPINE | SSH telnet console | `telnet 112.137.129.232:5006` | Routing policy push |
| **SONIC-LEAF-1** | **SSH telnet console** | `telnet 112.137.129.232:5010` | **Apply iptables** (ZT enforcement) |
| **SONIC-LEAF-2** | **SSH telnet console** | `telnet 112.137.129.232:5015` | **Apply iptables** (ZT enforcement) |
| IDS Suricata | REST + SSE | `:8765` / `:8766` | Subscribe alerts |

**Ghi chú:** SONiC-VS không support proper NETCONF/gNMI — cần dùng Linux shell qua telnet console hoặc SSH (nếu enable). Production SONiC sẽ có gNMI/NETCONF chuẩn.

### 9.2 Enforcement Targets — chỉ LEAF cần apply rule

| Switch | Cần apply microsegmentation? | Lý do |
|--------|:-:|------|
| SONIC-SPINE | ❌ | Pure transit, không terminate VLAN, không có host trực tiếp |
| **SONIC-LEAF-1** | ✅ | Terminate WEB+DB SVI, phải enforce intra-leaf (WEB→DB) + inter-leaf rules |
| **SONIC-LEAF-2** | ✅ | Terminate APP+MGT SVI, phải enforce intra-leaf (APP→MGT) + inter-leaf rules |

### 9.3 Suggested SDNC Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ ONAP SDNC AI Agent                                          │
│                                                             │
│  1. Subscribe SSE: GET http://10.10.6.238:8766/events       │
│  2. On P1 alert received:                                   │
│     a. Identify src_ip → determine LEAF (zone mapping)      │
│     b. Build iptables rule:                                 │
│        iptables -I FORWARD 1 -s <src_ip> -j DROP            │
│     c. Push qua SSH/telnet console tới LEAF                 │
│     d. Schedule auto-unblock (e.g., 5 min TTL)              │
│  3. Status feedback:                                        │
│     a. POST event "BLOCKED" về dashboard                    │
│     b. Log audit trail                                      │
└─────────────────────────────────────────────────────────────┘
```

### 9.4 Zone Mapping Helper (for SDNC)

```python
def ip_to_leaf(src_ip: str) -> str:
    """Map source IP → LEAF switch để biết apply rule ở đâu."""
    if src_ip.startswith("10.1.100.") or src_ip.startswith("10.1.200."):
        return "SONIC-LEAF-1"
    if src_ip.startswith("10.2.100.") or src_ip.startswith("10.2.50."):
        return "SONIC-LEAF-2"
    return None

def ip_to_zone(src_ip: str) -> str:
    if src_ip.startswith("10.1.100."): return "WEB"
    if src_ip.startswith("10.1.200."): return "DB"
    if src_ip.startswith("10.2.100."): return "APP"
    if src_ip.startswith("10.2.50."):  return "MGT"
    return None
```

---

## 10. Verification & Test Status

| Test | Result | Date |
|------|--------|------|
| 8-path connectivity matrix | 8/8 PASS | 2026-04-13 |
| 12-flow ZT policy enforcement | 12/12 correct | 2026-04-14 |
| Suricata detection (4 violations) | 4/4 detected | 2026-04-18 |
| End-to-end SC-1 → SC-5 | 5/5 PASS | 2026-04-19 |
| False Positive Rate (SC-5 baseline) | 0% | 2026-04-19 |
| Browser dashboard | 8/8 PASS | 2026-04-19 |
| **Total live alerts captured** | **38** | **2026-04-19** |
| **Intelligence Layer V2 (single-call) — 10-run eval** | | **2026-05-04** |
| — Outcome: ENFORCED | 10/10 PASS | 2026-05-04 |
| — M1 Alert→Decision avg | 4.75s | 2026-05-04 |
| — Confidence avg | 0.955 | 2026-05-04 |
| — Cerebras 400 fail rate | ~5-10% (mitigated via retry+fallback) | 2026-05-04 |
| **Intelligence Layer V3 (schema split) — 10-run eval** | | **2026-05-05** |
| — Outcome: ENFORCED | **10/10 PASS** | 2026-05-05 |
| — M3 Enforcement Correctness (correct IP) | **10/10 (100%)** | 2026-05-05 |
| — M1 Alert→Decision avg | **8.5s** (range 6.5-12.0s) | 2026-05-05 |
| — Agent latency avg | 6645ms (range 5009-10301ms) | 2026-05-05 |
| — Confidence | **0.92 consistent across all 10 runs** | 2026-05-05 |
| — **Cerebras 400 fail rate** | **0%** (Stage 1 schema simplified, 0 retries needed) | 2026-05-05 |
| — Stage 2 reasoning trace populated | 10/10 (3 hyp + 6.7 reasoning + 2.9 alts + 3.8 follow-up) | 2026-05-05 |
| — MITRE classification | T1021 / TA0008 (correct for SID 9000001) | 2026-05-05 |
| — Redis DB separation (DB 0 eval-flushable, DB 1 events preserved) | verified | 2026-05-05 |
| — 9-layer safety guardrails + L1+ injection + L4b off-target + L2+ semantic entropy | PASS | 2026-05-05 |
| Scenario compromise-web → SID 9000001 → V3 auto-block → restore | full round-trip verified | 2026-05-05 |

---

## 11. Files / Scripts Reference

| File | Purpose |
|------|---------|
| `/3s-com/zma/dc-fabric-setup/05-setup-all.py` | Full fabric setup automation |
| `/3s-com/zma/dc-fabric-setup/06-verify.py` | Connectivity matrix verification |
| `/3s-com/zma/dc-fabric-setup/07-apply-policy.py` | iptables apply/rollback (target for SDNC replacement) |
| `/3s-com/zma/dc-fabric-setup/07-iptables-leaf1.sh` | Raw iptables rules LEAF-1 |
| `/3s-com/zma/dc-fabric-setup/07-iptables-leaf2.sh` | Raw iptables rules LEAF-2 |
| `/3s-com/zma/dc-fabric-setup/08-verify-policy.py` | 12-flow policy verification |
| `/3s-com/zma/dc-fabric-setup/14-ids-webapi.py` | IDS REST API restore (legacy) |
| `/usr/local/bin/ids-api.py` (inside IDS VM) | Active REST API server (232 LOC, stdlib only) — source: `zma/suricata/ids-vm/ids-api.py` |
| `/etc/suricata/suricata-zt.yaml` (inside IDS VM) | Suricata config — source: `zma/suricata/ids-vm/suricata-zt.yaml` |
| `/etc/suricata/rules/zt-lab.rules` (inside IDS VM) | 21 active rules (8 ZT + 13 Yatesbury, SID …01–…52) — source: `zma/ids-vm/rules/zt-lab.rules` |
| `/3s-com/dataplane/bootstrap/web-host.sh` | WEB zone provisioning (banner :80 + sshd + shopper cron) |
| `/3s-com/dataplane/bootstrap/db-host.sh`  | DB zone provisioning (pg-mock :5432 SQL-aware + sshd) |
| `/3s-com/dataplane/bootstrap/app-host.sh` | APP zone provisioning (banner :8080 + sshd + noise→DB cron) |
| `/3s-com/dataplane/bootstrap/mgt-host.sh` | MGT zone provisioning (sshd + audit/scrape/logpull + scenario controllers) |
| `/tmp/paste_bootstrap.py` | Base64-encoded push of bootstrap script via GNS3 console proxy |

---

## 12. Intelligence Layer — Implementation Status (2026-05-05, V3)

All items previously listed as "open for SDNC Agent" are now complete via the Intelligence Layer service. V3 adds schema split, parallel reasoning, EventsStore, and Langfuse observability.

| Item | Status | Implementation |
|------|--------|---------------|
| Rule push to LEAF | ✅ DONE | Intelligence Layer → `POST ids-agent:8766/rules` → SF `/api/rules` → gNMI → nos-acl-bridge → iptables |
| Subscribe IDS SSE stream | ✅ DONE | `pipeline/consumer.py` SSE + flow poller (5s) → mirrors to EventsStore Redis DB 1 |
| Auto-block workflow (P1 alert → DROP) | ✅ DONE | V3 8-node pipeline, Stage 1 + parallel Stage 2 reasoning. Confidence gate ≥0.85 |
| Auto-unblock TTL | ✅ DONE | `ttl_seconds` field (3600s for P1, 1800s P2). Caller responsibility (agent maintains expire map) |
| Block event back to dashboard | ✅ DONE | Postgres + Redis cache + SSE `/stream` + Langfuse trace; Frontend `/api/intel/decisions` + 🧠 Reasoning modal |
| Audit trail / compliance log | ✅ DONE | Postgres `decisions` (V3: + primary_hypothesis, alternative_actions, follow_up_actions, mitre_*, reasoning_completed_at, trace_id) |
| LLM observability | ✅ DONE (V3) | Langfuse v2 self-hosted (port 3001), trace per alert (8 spans + 3 generations), token cost, retrospective scoring |
| Events buffer for Monitor F5 | ✅ DONE (V3) | EventsStore Redis DB 1 (sorted sets, 7-day TTL, max 100K events, hourly prune coroutine) |
| Knowledge graph visualization | ✅ DONE (V3) | pyvis HTML at `/kg/visualize` (30 nodes, 43 edges) |
| Cerebras 400 mitigation | ✅ DONE (V3) | Schema split — Stage 1 (9 scalar) ~0% parser fail, Stage 2 (4 arrays) fail-tolerant non-blocking |
| Reasoning trace for HITL review | ✅ DONE (V3) | Stage 2 outputs: 3 hypotheses + reasoning_steps + alternatives + rollback + follow-up + MITRE mapping |
| SSH/telnet connector to SONiC console | ❌ NOT needed | Route goes through SF gNMI — no direct console access required for enforcement |

**Architecture:** No direct SSH/console to SONiC needed. Control path is: Intelligence Layer → ids-agent (REST) → Secure Framework (gNMI mTLS) → nos-acl-bridge → iptables FORWARD. All persistence in LEAF ConfigDB (Redis DB4 internal to LEAF) — survives restart.

**V3 storage layout** (logical separation):
- LEAF Redis (ConfigDB DB4): rules persist on switch, restart-survivable
- Control-plane Redis DB 0: agent state (dedup, response cache, rate limiter) — eval-flushable
- Control-plane Redis DB 1: EventsStore (alerts + flows buffer for frontend Monitor) — preserved across eval
- Postgres `zerotrust`: decisions audit trail (164+ records), retrospective labels
- Postgres `langfuse`: LLM observability traces (10+ traces per eval session)
