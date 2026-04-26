#!/usr/bin/env bash
# nos-acl-bridge deploy script — run on each LEAF after copying repo
# Usage: sudo bash setup.sh [--leaf1|--leaf2]
set -euo pipefail

INSTALL_DIR="/opt/nos-acl-bridge"
CERTS_DIR="/etc/nos-acl-bridge/certs"
SERVICE_DST="/etc/systemd/system/nos-acl-bridge.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Determine which leaf cert set to use
LEAF="leaf-1"
if [[ "${1:-}" == "--leaf2" ]]; then LEAF="leaf-2"; fi
CERT_SRC="$SCRIPT_DIR/../output_3snos/sonic/$LEAF"

echo "=== nos-acl-bridge setup ($LEAF) ==="

# 1. Python deps
echo "[1/6] Installing Python dependencies..."
pip3 install --quiet grpcio grpcio-tools cryptography redis

# 2. Download OpenConfig gNMI protos
echo "[2/6] Downloading gNMI protos..."
mkdir -p "$INSTALL_DIR/proto"
curl -fsSL \
    "https://raw.githubusercontent.com/openconfig/gnmi/v0.10.0/proto/gnmi/gnmi.proto" \
    -o "$INSTALL_DIR/proto/gnmi.proto"
curl -fsSL \
    "https://raw.githubusercontent.com/openconfig/gnmi/v0.10.0/proto/gnmi_ext/gnmi_ext.proto" \
    -o "$INSTALL_DIR/proto/gnmi_ext.proto"

# 3. Generate Python gRPC stubs
echo "[3/6] Generating gNMI Python stubs..."
mkdir -p "$INSTALL_DIR/bridge"
python3 -m grpc_tools.protoc \
    -I "$INSTALL_DIR/proto" \
    --python_out="$INSTALL_DIR/bridge" \
    --grpc_python_out="$INSTALL_DIR/bridge" \
    "$INSTALL_DIR/proto/gnmi.proto" \
    "$INSTALL_DIR/proto/gnmi_ext.proto"

# 4. Install bridge Python files
echo "[4/6] Installing bridge modules..."
cp "$SCRIPT_DIR/bridge/__init__.py"      "$INSTALL_DIR/bridge/"
cp "$SCRIPT_DIR/bridge/iptables.py"      "$INSTALL_DIR/bridge/"
cp "$SCRIPT_DIR/bridge/validators.py"    "$INSTALL_DIR/bridge/"
cp "$SCRIPT_DIR/bridge/recovery.py"      "$INSTALL_DIR/bridge/"
cp "$SCRIPT_DIR/bridge/nos_acl_bridge.py" "$INSTALL_DIR/bridge/"
chmod +x "$INSTALL_DIR/bridge/nos_acl_bridge.py"

# 5. Deploy certs
echo "[5/6] Deploying certs for $LEAF..."
mkdir -p "$CERTS_DIR"
chmod 700 "$CERTS_DIR"
if [[ -d "$CERT_SRC" ]]; then
    cp "$CERT_SRC/server.crt"              "$CERTS_DIR/"
    cp "$CERT_SRC/server.key"              "$CERTS_DIR/"
    cp "$CERT_SRC/trustedCertificates.crt" "$CERTS_DIR/"
    chmod 600 "$CERTS_DIR/"*
    echo "  Certs deployed from $CERT_SRC"
else
    echo "  WARNING: $CERT_SRC not found — copy certs manually to $CERTS_DIR"
    echo "    server.crt, server.key, trustedCertificates.crt"
fi

# 6. Systemd service
echo "[6/6] Installing systemd service..."
cp "$SCRIPT_DIR/nos-acl-bridge.service" "$SERVICE_DST"
systemctl daemon-reload

echo ""
echo "Setup complete."
echo "  Start:   systemctl enable --now nos-acl-bridge"
echo "  Logs:    journalctl -fu nos-acl-bridge"
echo "  Status:  systemctl status nos-acl-bridge"
echo ""
echo "Quick smoke test (from GNS3VM):"
echo "  gnmic -a 192.168.122.20:9339 --tls-cert gnmic-test/client.crt \\"
echo "        --tls-key gnmic-test/client.key --tls-ca gnmic-test/trustedCertificates.crt \\"
echo "        capabilities"
