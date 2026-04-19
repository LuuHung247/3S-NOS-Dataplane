# Plan: Suricata IDS Inline trong GNS3 Spine-Leaf Lab

## Boi canh

Zero Trust microsegmentation (iptables) da hoan thanh (12/12 verified).
Can them Suricata IDS vao topology GNS3 de kien truc giong datacenter thuc te.
Trong DC that, IDS duoc deploy qua TAP/SPAN port — Hub trong GNS3 mo phong chinh xac dieu nay.

## Backup

- Topology: `/3s-com/zma/backups/micro-segmentation-lab_20260415_031523.gns3.bak`
- Links: `/3s-com/zma/backups/links_backup.json`
- Nodes: `/3s-com/zma/backups/nodes_backup.json`
- Rollback: Copy file .bak ve lai `/opt/gns3/projects/.../micro-segmentation-lab.gns3` roi reload project

## Kien truc muc tieu

```
                           NAT1
                            |
                     SONIC-SPINE
                      /         \
                 TAP-Hub1     TAP-Hub2        ← Ethernet Hub = Network TAP
                 /   |         |   \
            LEAF-1   |      LEAF-2   |
            /   \    |       /   \   |
       Alpine-1  2   |  Alpine-3  5  |
        (WEB) (DB)   |   (APP) (MGT) |
                     |               |
                  IDS-Suricata ──────┘
                  (eth0=Hub1, eth1=Hub2)
```

### Tai sao Hub-based TAP giong DC that?

- Trong datacenter thuc te, IDS (Suricata/Snort/Zeek) ket noi vao **SPAN port** hoac **Network TAP**
- Traffic duoc mirror (copy) toi IDS — IDS chi nghe, khong can thiep vao luong traffic
- Hub trong GNS3 = Layer 2 repeater, forward moi frame toi tat ca ports → tuong duong SPAN
- SPINE va LEAF giao tiep binh thuong qua Hub — transparent, khong thay doi IP/MAC/VLAN
- Day la kien truc **out-of-band IDS** chuan theo NIST 800-207

### Tai sao khong dung GNS3 API capture?

- GNS3 API capture la tinh nang debug cua phan mem, khong ton tai trong DC that
- Khong co node IDS nao trong topology → khong giong kien truc that
- Khong demo duoc "IDS appliance" cho thesis

## Chi tiet trien khai

### Step 1: Tao 2 Ethernet Hub qua GNS3 API

| Hub | Vi tri | Chuc nang |
|-----|--------|-----------|
| TAP-Hub1 | Giua SPINE va LEAF-1 | Mirror traffic SPINE↔LEAF-1 toi IDS |
| TAP-Hub2 | Giua SPINE va LEAF-2 | Mirror traffic SPINE↔LEAF-2 toi IDS |

API: `POST /v2/projects/{pid}/templates/b4503ea9-d6b6-3695-9fe4-1db3b39290b0`
Hub la built-in GNS3 node, 8 ports, khong can RAM/CPU.

### Step 2: Tao IDS-Suricata Alpine node

- Template: Alpine `23a9125b-0276-4c4b-8636-cba052e549a9`
- RAM: 512MB, 2 vCPU (giong cac Alpine khac)
- 2 adapters: eth0 → Hub1, eth1 → Hub2
- Vi tri tren canvas: giua 2 Hub

### Step 3: Rewire links (QUAN TRONG NHAT)

**Xoa 2 link cu:**
- SPINE:adapter1 ↔ LEAF-1:adapter0 (link `251176e5-...`)
- SPINE:adapter2 ↔ LEAF-2:adapter0 (link `408309e9-...`)

**Tao 6 link moi:**

| # | Tu | Toi | Muc dich |
|---|-----|-----|----------|
| 1 | SPINE:adapter1 | Hub1:port0 | Uplink SPINE → Hub1 |
| 2 | Hub1:port1 | LEAF-1:adapter0 | Hub1 → LEAF-1 |
| 3 | Hub1:port2 | IDS:adapter0 | Mirror toi IDS eth0 |
| 4 | SPINE:adapter2 | Hub2:port0 | Uplink SPINE → Hub2 |
| 5 | Hub2:port1 | LEAF-2:adapter0 | Hub2 → LEAF-2 |
| 6 | Hub2:port2 | IDS:adapter1 | Mirror toi IDS eth1 |

**Luu y Hub port numbering**: adapter_number=0, port_number=0/1/2/...

### Step 4: Start nodes moi

Start Hub1, Hub2, IDS-Suricata qua GNS3 API.

### Step 5: Re-apply fabric setup

Sau khi rewire, interface co the flap → forwarding flags reset.
- Chay `05-setup-all.py` (forwarding + routes + ARP)
- Config IP cho IDS Alpine: `ip link set eth0 up promisc on; ip link set eth1 up promisc on`
- Verify `06-verify.py` → 8/8 PASS
- Apply policy `07-apply-policy.py apply`
- Verify `08-verify-policy.py` → 12/12 correct

### Step 6: Cai Suricata tren IDS node

Trong IDS Alpine VM (qua console):
```
apk update
apk add suricata tcpdump
```

Hoac: Chay Suricata tren gns3vm host doc pcap tu GNS3 capture tren Hub links.
→ Khien nghi: **ca 2** — Suricata tren host (manh), tcpdump tren IDS node (visual demo)

### Step 7: Deploy Suricata config + rules

- Copy `suricata-zt.yaml` va `rules/zt-lab.rules` vao IDS node (hoac dung tren host)
- Chay Suricata: `suricata -c suricata-zt.yaml -i eth0` (live) hoac `-r capture.pcap` (offline)

### Step 8: Verification + Demo

Tao script `11-ids-demo.py`:
1. Generate traffic vi pham tu Alpine consoles:
   - WEB→DB (sid:9000001) — microsegmentation bypass
   - DB→outbound (sid:9000002) — data exfiltration
   - APP→WEB (sid:9000003) — lateral movement
2. Chay Suricata analyze
3. Parse eve.json → bao cao alerts
4. Expected: Suricata detect tat ca violations

## Scripts can tao

| File | Mo ta |
|------|-------|
| `09-deploy-ids.py` | GNS3 API: tao Hub + IDS + rewire links + rollback |
| `10-suricata-analyze.py` | Chay Suricata, parse alerts, bao cao |
| `11-ids-demo.py` | Demo: tao violations + detect + report |

## Rollback plan

Neu Step 3 (rewire) lam hong connectivity:
1. Xoa 6 link moi + Hub + IDS nodes
2. Tao lai 2 link cu SPINE↔LEAF truc tiep
3. Chay `05-setup-all.py`
4. Hoac: restore file `.gns3.bak` + reload GNS3 project

Script `09-deploy-ids.py` se co option `--rollback` de tu dong lam viec nay.

## GNS3 API IDs

| Entity | ID |
|--------|-----|
| Project | `b6bf1cd6-8d58-41d4-941c-893020abd2a3` |
| SPINE | `7364a9ca-a155-4328-832d-fa3b818dd2e9` |
| LEAF-1 | `b49505fd-4f50-4659-bf39-9d548190663f` |
| LEAF-2 | `c62b0bdd-3bd2-4b84-a531-36450236378e` |
| Link SPINE-LEAF1 | `251176e5-1197-427f-b404-32fe0a429188` |
| Link SPINE-LEAF2 | `408309e9-c780-408b-ae77-56d3db60ccaa` |
| Hub template | `b4503ea9-d6b6-3695-9fe4-1db3b39290b0` |
| Alpine template | `23a9125b-0276-4c4b-8636-cba052e549a9` |
