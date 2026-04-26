#!/usr/bin/env python3
"""
15-deploy-bridge.py — Deploy nos-acl-bridge to LEAF-1 + LEAF-2
================================================================
Chạy từ: dis@gns3vm  (trong /3s-com/zma/dc-fabric-setup/)

Bước thực hiện:
  1. Download gnmi.proto + gnmi_ext.proto, generate Python stubs (grpcio-tools)
  2. Start HTTP server :8888 serving /3s-com/zma/
  3. Với từng LEAF (telnet console):
     a. pip3 install grpcio cryptography redis
     b. mkdir /opt/nos-acl-bridge/bridge /etc/nos-acl-bridge/certs
     c. wget bridge files + generated stubs
     d. wget server cert/key/CA cho đúng LEAF
     e. cài systemd service + enable + start

Usage:
  python3 15-deploy-bridge.py [--leaf1|--leaf2|--both]   (default: --both)
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
CONSOLE_HOST = "127.0.0.1"
NODES = {
    "LEAF-1": {"port": 5010, "user": "admin", "password": "YourPaSsWoRd",
               "cert_subdir": "leaf-1"},
    "LEAF-2": {"port": 5015, "user": "admin", "password": "YourPaSsWoRd",
               "cert_subdir": "leaf-2"},
}

BASE_DIR     = Path("/3s-com/zma")
BRIDGE_DIR   = BASE_DIR / "nos-acl-bridge"
GEN_DIR      = BRIDGE_DIR / "generated"
CERTS_BASE   = BASE_DIR / "output_3snos"
PROTO_DIR    = GEN_DIR / "proto"
HTTP_PORT    = 8888
GNS3VM_IP    = "192.168.122.1"   # virbr0 — reachable from LEAFs via SPINE

BRIDGE_FILES = [
    "bridge/__init__.py",
    "bridge/iptables.py",
    "bridge/validators.py",
    "bridge/recovery.py",
    "bridge/nos_acl_bridge.py",
]
GEN_STUBS = [
    "generated/gnmi_pb2.py",
    "generated/gnmi_pb2_grpc.py",
]
INSTALL_DIR_LEAF  = "/opt/nos-acl-bridge"
CERTS_DIR_LEAF    = "/etc/nos-acl-bridge/certs"
SERVICE_NAME      = "nos-acl-bridge"
SERVICE_FILE_LEAF = f"/etc/systemd/system/{SERVICE_NAME}.service"

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Console helpers (same pattern as 07-apply-policy.py)
# ---------------------------------------------------------------------------

def console_connect(node_name):
    cfg = NODES[node_name]
    s = socket.socket()
    s.connect((CONSOLE_HOST, cfg["port"]))
    s.settimeout(3)

    def drain(w=1.5):
        time.sleep(w)
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

    drain(0.5)
    s.send(b"\n"); drain(1)
    s.send(f"{cfg['user']}\n".encode()); drain(1)
    s.send(f"{cfg['password']}\n".encode()); drain(3)
    return s, drain


def run_cmd(s, drain, cmd, wait=3.0, show=True):
    s.send((cmd + "\n").encode())
    out = drain(wait)
    if show:
        for line in out.splitlines():
            line = line.rstrip()
            if not line:
                continue
            if line.startswith("admin@") and line.endswith("$"):
                continue
            print(f"    {line}")
    return out


# ---------------------------------------------------------------------------
# Step 1: Generate gNMI proto stubs on GNS3VM
# ---------------------------------------------------------------------------

PROTO_CLEAN_URL = "https://raw.githubusercontent.com/openconfig/gnmi/v0.10.0/proto/gnmi/gnmi.proto"


def _make_clean_proto(raw: str) -> str:
    """Strip gnmi_ext dependency and empty extend block from gnmi.proto."""
    import re
    lines = raw.splitlines()
    # Remove gnmi_ext import + go/java options + gnmi_service usages
    lines = [l for l in lines if not any(x in l for x in (
        "gnmi_ext", "go_package", "java_", "gnmi_service",
    ))]
    # Remove now-empty 'extend google.protobuf.FileOptions { }' block
    text = "\n".join(lines)
    text = re.sub(r'extend google\.protobuf\.FileOptions \{[^}]*\}', '', text, flags=re.DOTALL)
    return text


def generate_stubs():
    print("[1/4] Checking gNMI proto stubs...")
    needed = [GEN_DIR / f for f in ("gnmi_pb2.py", "gnmi_pb2_grpc.py", "__init__.py")]
    if all(f.exists() for f in needed):
        print("  Stubs already generated, skip.")
        return

    GEN_DIR.mkdir(parents=True, exist_ok=True)
    tmp_proto = Path(tempfile.mkdtemp()) / "gnmi.proto"

    print("  Downloading gnmi.proto...")
    urllib.request.urlretrieve(PROTO_CLEAN_URL, tmp_proto)
    tmp_proto.write_text(_make_clean_proto(tmp_proto.read_text()))

    result = subprocess.run(
        [
            sys.executable, "-m", "grpc_tools.protoc",
            f"-I{tmp_proto.parent}",
            f"--python_out={GEN_DIR}",
            f"--grpc_python_out={GEN_DIR}",
            str(tmp_proto),
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("  ERROR generating stubs:\n", result.stderr)
        sys.exit(1)

    # Fix absolute import → relative inside the generated package
    grpc_stub = GEN_DIR / "gnmi_pb2_grpc.py"
    grpc_stub.write_text(grpc_stub.read_text().replace(
        "import gnmi_pb2 as gnmi__pb2",
        "from . import gnmi_pb2 as gnmi__pb2",
    ))
    (GEN_DIR / "__init__.py").write_text("")

    print("  Stubs generated OK.")
    for f in sorted(GEN_DIR.glob("*.py")):
        print(f"    {f.name}")


# ---------------------------------------------------------------------------
# Step 2: HTTP server
# ---------------------------------------------------------------------------

def start_http_server():
    print(f"[2/4] Starting HTTP server on {GNS3VM_IP}:{HTTP_PORT} ...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(HTTP_PORT),
         "--directory", str(BASE_DIR), "--bind", "0.0.0.0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    if proc.poll() is not None:
        print("  ERROR: HTTP server failed to start")
        sys.exit(1)
    print(f"  Serving {BASE_DIR} at http://{GNS3VM_IP}:{HTTP_PORT}/")
    return proc


# ---------------------------------------------------------------------------
# Step 3: Deploy to one LEAF
# ---------------------------------------------------------------------------

def deploy_leaf(node_name: str):
    cfg = NODES[node_name]
    leaf_id = cfg["cert_subdir"]     # leaf-1 or leaf-2
    base_url = f"http://{GNS3VM_IP}:{HTTP_PORT}"

    print(f"\n[3/4] Deploying to {node_name} (console :{cfg['port']}) ...")
    s, drain = console_connect(node_name)

    def cmd(c, wait=4.0):
        print(f"  $ {c[:80]}")
        run_cmd(s, drain, c, wait=wait)

    def fetch(url: str, dest: str, wait: float = 10.0):
        cmd(f"sudo curl -fsSL -o {dest} '{url}'", wait=wait)

    # Dirs (including generated/ subdir)
    cmd(f"sudo mkdir -p {INSTALL_DIR_LEAF}/bridge {INSTALL_DIR_LEAF}/generated {CERTS_DIR_LEAF}")
    cmd(f"sudo chmod 700 {CERTS_DIR_LEAF}")

    # Python deps — protobuf>=5.26 required by grpcio 1.70 generated stubs
    print("  Installing Python deps — may take ~90s...")
    cmd("sudo pip3 install --quiet --upgrade grpcio protobuf cryptography redis 2>&1 | tail -3", wait=120)

    # curl bridge files
    for rel in BRIDGE_FILES:
        fetch(f"{base_url}/nos-acl-bridge/{rel}", f"{INSTALL_DIR_LEAF}/{rel}")

    # curl generated stubs
    for rel in GEN_STUBS:
        fetch(f"{base_url}/nos-acl-bridge/{rel}", f"{INSTALL_DIR_LEAF}/{rel}")
    fetch(f"{base_url}/nos-acl-bridge/generated/__init__.py",
          f"{INSTALL_DIR_LEAF}/generated/__init__.py")

    # Certs (leaf-specific) — chmod each file explicitly, avoid glob
    for cert_file in ("server.crt", "server.key", "trustedCertificates.crt"):
        dest = f"{CERTS_DIR_LEAF}/{cert_file}"
        fetch(f"{base_url}/output_3snos/sonic/{leaf_id}/{cert_file}", dest)
        cmd(f"sudo chmod 600 {dest}")

    # systemd service file
    service_src = BRIDGE_DIR / "nos-acl-bridge.service"
    if service_src.exists():
        fetch(f"{base_url}/nos-acl-bridge/nos-acl-bridge.service", SERVICE_FILE_LEAF)
    else:
        print("  WARNING: nos-acl-bridge.service not found, skipping")

    cmd("sudo systemctl daemon-reload")
    cmd(f"sudo systemctl enable {SERVICE_NAME}")
    cmd(f"sudo systemctl restart {SERVICE_NAME}", wait=5)
    cmd(f"sudo systemctl is-active {SERVICE_NAME}", wait=3)
    cmd(f"sudo journalctl -u {SERVICE_NAME} --no-pager -n 20", wait=4)

    s.close()
    print(f"  {node_name} deploy done.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "--both"
    targets = []
    if arg in ("--leaf1", "--both"):
        targets.append("LEAF-1")
    if arg in ("--leaf2", "--both"):
        targets.append("LEAF-2")
    if not targets:
        print(f"Usage: python3 {sys.argv[0]} [--leaf1|--leaf2|--both]")
        sys.exit(1)

    generate_stubs()
    http_proc = start_http_server()

    try:
        for node in targets:
            deploy_leaf(node)
    finally:
        http_proc.terminate()
        print("\n[4/4] HTTP server stopped.")

    print("\n=== Deploy complete ===")
    print("Verify:")
    print(f"  gnmic -a 192.168.122.20:9339 \\")
    print(f"    --tls-cert ../gnmic-test/client.crt \\")
    print(f"    --tls-key  ../gnmic-test/client.key \\")
    print(f"    --tls-ca   ../gnmic-test/trustedCertificates.crt \\")
    print(f"    capabilities")


if __name__ == "__main__":
    main()
