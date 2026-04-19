# Datacenter Fabric Setup — SONiC-VS Spine-Leaf on GNS3

Tài liệu và scripts để triển khai datacenter fabric hoàn chỉnh với east-west routing
trên GNS3 sử dụng SONiC Virtual Switch (VS).

## Tổng quan kiến trúc

```
                    ┌──────────────┐
                    │  SONIC-SPINE │
                    │  10.0.1.1/30 │ eth1 ←→ LEAF-1
                    │  10.0.2.1/30 │ eth2 ←→ LEAF-2
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     ┌────────┴────────┐      ┌────────┴────────┐
     │  SONIC-LEAF-1   │      │  SONIC-LEAF-2   │
     │ Uplink: eth0    │      │ Uplink: eth0    │
     │ 10.0.1.2/30     │      │ 10.0.2.2/30     │
     │                 │      │                 │
     │ Vlan100: eth2   │      │ Vlan100: eth2   │
     │ 10.1.100.1/24   │      │ 10.2.100.1/24   │
     │                 │      │                 │
     │ Vlan200: eth3   │      │ Vlan300: eth3   │
     │ 10.1.200.1/24   │      │ 10.2.50.1/24    │
     └──┬─────────┬────┘      └──┬─────────┬────┘
        │         │              │         │
   ┌────┴───┐ ┌──┴─────┐  ┌────┴───┐ ┌───┴────┐
   │Alpine-1│ │Alpine-2│  │Alpine-3│ │Alpine-5│
   │  WEB   │ │   DB   │  │  APP   │ │  MGT   │
   │.100.10 │ │.200.10 │  │.100.10 │ │ .50.10 │
   └────────┘ └────────┘  └────────┘ └────────┘
```

## Vấn đề chính và cách giải quyết

### 1. SONiC-VS interface mapping (ethX vs EthernetY)
SONiC-VS tạo 2 loại interface cho mỗi port vật lý:
- `ethX` — kernel interface (nhận/gửi packet thực tế)
- `EthernetY` — SONiC interface (quản lý bởi orchagent/syncd)

Mapping trên GNS3: `adapter N` → `ethN` → `Ethernet(N*4)` (trừ adapter0 = management)

### 2. Root cause cross-leaf failure (QUAN TRỌNG NHẤT)
SONiC-VS chỉ set `forwarding=1` cho `EthernetX` interfaces.
Các interface khác (`eth0`, `Vlan100`, `Vlan300`, `Bridge`) đều có `forwarding=0`.

Khi packet cross-leaf đi: `eth0 → kernel route → Vlan100 → Bridge → Ethernet4 → Alpine`,
kernel kiểm tra `conf.{iface}.forwarding` trên cả input interface (eth0) và output interface (Vlan100).
Nếu bất kỳ interface nào có `forwarding=0`, packet bị drop với `EHOSTUNREACH`.

### 3. Static ARP cần thiết
SONiC-VS bridge không tự reply ARP từ SVI đến Alpine hosts trong mọi trường hợp.
Cần thêm static ARP entries trên LEAF để đảm bảo packet delivery.

## Files trong folder này

| File | Mô tả |
|------|--------|
| `README.md` | Tài liệu này |
| `01-fix-forwarding.sh` | Script chính: enable forwarding trên tất cả interfaces |
| `02-setup-leaf1.sh` | Config LEAF-1: routes, ARP, rp_filter |
| `03-setup-leaf2.sh` | Config LEAF-2: routes, ARP, rp_filter |
| `04-setup-spine.sh` | Config SPINE: routes, forwarding |
| `05-setup-all.py` | Script Python tự động chạy tất cả qua console |
| `06-verify.py` | Script kiểm tra connectivity matrix |

## Cách sử dụng

### Tự động (chạy từ gns3vm):
```bash
# Chạy toàn bộ setup + verify
python3 05-setup-all.py

# Chỉ verify connectivity
python3 06-verify.py
```

### Thủ công (SSH/console vào từng node):
```bash
# Trên mỗi SONiC node:
bash 01-fix-forwarding.sh

# Trên LEAF-1:
bash 02-setup-leaf1.sh

# Trên LEAF-2:
bash 03-setup-leaf2.sh

# Trên SPINE:
bash 04-setup-spine.sh
```

## Lưu ý quan trọng
- Scripts cần chạy lại SAU MỖI LẦN `config reload` hoặc reboot SONiC
- SONiC password: `YourPaSsWoRd`
- Alpine login: `root` (không password)
- Diagnostic command: `ip route get <dst> from <src> iif <interface>`
