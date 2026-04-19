#!/bin/bash
# Test ACL trên LEAF-1 — chạy script này từ máy có thể telnet vào 112.137.129.232:5010
# Hoặc SSH vào SONIC-SPINE rồi jump sang LEAF-1

SSH="ssh -o StrictHostKeyChecking=no admin@192.168.122.187"

echo "=== [1] Current state LEAF-1 ==="
$SSH "ssh -o StrictHostKeyChecking=no admin@10.0.1.2 'show vlan brief; show ip interfaces; show acl table; show acl rule'"

echo ""
echo "=== [2] Apply test ACL — Block ICMP từ VLAN200 (DB) sang VLAN100 (WEB) ==="
# ACL này: DB zone không được initiate connection sang WEB zone
$SSH "ssh -o StrictHostKeyChecking=no admin@10.0.1.2 '
sudo config acl add table BLOCK_DB_TO_WEB L3 --description \"Block DB zone initiating to WEB\" --ports Vlan200
sudo config acl add rule BLOCK_DB_TO_WEB RULE_10 --priority 10 --src-ip 10.1.200.0/24 --dst-ip 10.1.100.0/24 --action drop
sudo config acl add rule BLOCK_DB_TO_WEB DEFAULT_RULE --priority 1 --action forward
show acl table
show acl rule
'"

echo ""
echo "=== [3] Test từ Alpine-2 (DB) ping Alpine-1 (WEB) — phải BLOCK ==="
echo "Chạy lệnh sau trên Alpine-2 (telnet 5011):"
echo "  ping 10.1.100.10 -c 3"
echo "Expected: 100% packet loss"

echo ""
echo "=== [4] Test từ Alpine-1 (WEB) ping Alpine-2 (DB) — phải PASS ==="
echo "Chạy lệnh sau trên Alpine-1 (telnet 5008):"
echo "  ping 10.1.200.10 -c 3"
echo "Expected: 0% packet loss (WEB initiate sang DB OK)"
