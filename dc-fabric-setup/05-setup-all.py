#!/usr/bin/env python3
"""
05-setup-all.py — Tự động config tất cả SONiC nodes qua telnet console
===========================================================================
Chạy từ: dis@gns3vm (máy host GNS3)
Chức năng: Kết nối tới console của SPINE, LEAF-1, LEAF-2 và chạy commands setup.

Script này thực hiện:
1. Login vào từng SONiC node qua telnet console
2. Enable forwarding trên tất cả interfaces (01-fix-forwarding.sh)
3. Thêm cross-leaf routes (02/03/04-setup-*.sh)
4. Thêm static ARP entries
5. Verify cơ bản (ping gateway từ mỗi LEAF)

Tại sao dùng console thay vì SSH:
- SSH qua ProxyJump có vấn đề với nhiều SSH keys trên gns3vm
- Console (telnet) luôn hoạt động và không cần key management
"""

import socket
import time
import sys


# =============================================================================
# CONFIG: Console ports và credentials
# =============================================================================
NODES = {
    "SPINE":  {"port": 5006, "user": "admin", "password": "YourPaSsWoRd"},
    "LEAF-1": {"port": 5010, "user": "admin", "password": "YourPaSsWoRd"},
    "LEAF-2": {"port": 5015, "user": "admin", "password": "YourPaSsWoRd"},
}

CONSOLE_HOST = "127.0.0.1"  # GNS3 VM localhost


# =============================================================================
# COMMANDS: Những gì cần chạy trên mỗi node
# =============================================================================

# Chạy trên TẤT CẢ nodes: enable forwarding + disable rp_filter
COMMON_CMDS = [
    # Enable forwarding trên mọi interface
    'sudo sh -c "for f in /proc/sys/net/ipv4/conf/*/forwarding; do echo 1 > $f; done"',
    # Disable reverse path filter
    'sudo sh -c "for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done"',
]

# SPINE: routes giữa 2 LEAFs
SPINE_CMDS = [
    "sudo ip route replace 10.1.0.0/16 via 10.0.1.2 dev eth1",
    "sudo ip route replace 10.2.0.0/16 via 10.0.2.2 dev eth2",
]

# LEAF-1: route tới LEAF-2 subnets + static ARP cho Alpine-1, Alpine-2
LEAF1_CMDS = [
    "sudo ip route add 10.2.0.0/16 via 10.0.1.1 dev eth0 2>/dev/null || sudo ip route replace 10.2.0.0/16 via 10.0.1.1 dev eth0",
    "sudo ip neigh replace 10.1.100.10 lladdr 0c:ec:b2:6c:00:00 dev Vlan100 nud permanent",
    "sudo ip neigh replace 10.1.200.10 lladdr 0c:ce:e0:ff:00:00 dev Vlan200 nud permanent",
]

# LEAF-2: route tới LEAF-1 subnets + static ARP cho Alpine-3, Alpine-5
LEAF2_CMDS = [
    "sudo ip route add 10.1.0.0/16 via 10.0.2.1 dev eth0 2>/dev/null || sudo ip route replace 10.1.0.0/16 via 10.0.2.1 dev eth0",
    "sudo ip neigh replace 10.2.100.10 lladdr 0c:87:e5:f0:00:00 dev Vlan100 nud permanent",
    "sudo ip neigh replace 10.2.50.10 lladdr 0c:c8:49:9e:00:00 dev Vlan300 nud permanent",
]


# =============================================================================
# CONSOLE HELPER: Kết nối và chạy commands qua telnet
# =============================================================================
def console_run(node_name, commands, verify_cmds=None):
    """Kết nối tới SONiC console, login, chạy commands."""
    cfg = NODES[node_name]
    port = cfg["port"]
    user = cfg["user"]
    pwd = cfg["password"]

    print(f"\n{'='*60}")
    print(f"  {node_name} (console port {port})")
    print(f"{'='*60}")

    try:
        s = socket.socket()
        s.connect((CONSOLE_HOST, port))
        s.settimeout(2)
    except ConnectionRefusedError:
        print(f"  ERROR: Cannot connect to port {port}. Is {node_name} running?")
        return False

    def read_all(wait=1):
        time.sleep(wait)
        out = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                out += d
        except (socket.timeout, OSError):
            pass
        return out.decode(errors="ignore")

    def cmd(c, wait=3):
        s.send((c + "\n").encode())
        return read_all(wait)

    # Login sequence
    read_all(0.5)
    s.send(b"\n")
    read_all(1)
    s.send(f"{user}\n".encode())
    read_all(1)
    s.send(f"{pwd}\n".encode())
    login_result = read_all(3)

    if "admin@sonic" not in login_result and "\\$" not in login_result:
        # Có thể đã logged in sẵn
        pass

    # Chạy commands
    for c in commands:
        print(f"  > {c[:70]}{'...' if len(c) > 70 else ''}")
        cmd(c)

    # Chạy verify commands nếu có
    if verify_cmds:
        print(f"  --- Verify ---")
        for c in verify_cmds:
            r = cmd(c)
            # In kết quả (bỏ prompt)
            for line in r.split("\n"):
                line = line.strip()
                if line and "admin@sonic" not in line and line != c:
                    print(f"  {line}")

    s.close()
    return True


# =============================================================================
# MAIN
# =============================================================================
def main():
    print("=" * 60)
    print("  DC Fabric Setup — SONiC-VS Spine-Leaf")
    print("  Configuring all nodes for full east-west routing")
    print("=" * 60)

    # SPINE
    console_run("SPINE", COMMON_CMDS + SPINE_CMDS, verify_cmds=[
        'ip route | grep -E "10\\.[12]\\.0"',
    ])

    # LEAF-1
    console_run("LEAF-1", COMMON_CMDS + LEAF1_CMDS, verify_cmds=[
        'ip route | grep "10.2"',
        'ip neigh show dev Vlan100 | grep PERMANENT',
        'ip neigh show dev Vlan200 | grep PERMANENT',
        'ping -c 1 -W 2 10.1.100.10',
    ])

    # LEAF-2
    console_run("LEAF-2", COMMON_CMDS + LEAF2_CMDS, verify_cmds=[
        'ip route | grep "10.1"',
        'ip neigh show dev Vlan100 | grep PERMANENT',
        'ip neigh show dev Vlan300 | grep PERMANENT',
        'ping -c 1 -W 2 10.2.100.10',
    ])

    print(f"\n{'='*60}")
    print("  Setup complete! Run 06-verify.py to test connectivity.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
