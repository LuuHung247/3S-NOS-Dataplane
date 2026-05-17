#!/usr/bin/env python3
from __future__ import annotations

"""3S-NOS nos-acl-bridge — gNMI server on :9339 with mTLS.

Architecture (Option D-revised):
  SF Lớp 4 (gNMI pool) → :9339 (this daemon, mTLS) → ConfigDB DB 4 + iptables FORWARD

Path convention (gNMI):
  origin : nos-iptables
  elem[0]: name=nos-iptables   (YANG container)
  elem[1]: name=rule, key={rule-id: <value>}

Set update val: JSON_IETF containing rule fields (rule-id may be in key or body).
Set delete: path only, no val — removes the rule from ConfigDB + iptables.
Get:        returns current rule state from ConfigDB DB 4.
"""
import json
import logging
import os
import signal
import sys
import time
from concurrent import futures
from typing import Optional

import grpc
import redis
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Generated stubs live at /opt/nos-acl-bridge/generated/ (one level up from bridge/)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from generated import gnmi_pb2, gnmi_pb2_grpc

from iptables import apply_rule, remove_rule
from recovery import reconcile_on_startup
from iptables import ensure_base_rules
from validators import ValidationError, enforce_rbac, validate_rule

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CERTS_DIR = os.environ.get("NOS_BRIDGE_CERTS", "/etc/nos-acl-bridge/certs")
BRIDGE_PORT = int(os.environ.get("NOS_BRIDGE_PORT", 9339))
CONFIGDB_ID = 4
SNAPSHOT_DB_ID = 50
TABLE_PREFIX = "NOS_IPTABLES_RULE"
REDIS_SOCKET = "/var/run/redis/redis.sock"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("nos-acl-bridge")

# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _open_redis(db: int) -> redis.Redis:
    # SONiC Redis unix socket requires 'redis' group — use TCP instead
    if os.path.exists(REDIS_SOCKET):
        try:
            r = redis.Redis(unix_socket_path=REDIS_SOCKET, db=db)
            r.ping()
            return r
        except Exception:
            pass
    return redis.Redis(host="localhost", port=6379, db=db)


def _write_configdb(r: redis.Redis, rule: dict) -> None:
    rule_id = rule["rule-id"]
    key = f"{TABLE_PREFIX}|{rule_id}"
    fields = {
        "chain":       rule.get("chain", "FORWARD"),
        "action":      rule["action"],
        "priority":    str(rule.get("priority", 1000)),
        "source":      rule.get("source", "sdnc"),
        "protocol":    rule.get("protocol", "all"),
        "ttl-seconds": str(rule.get("ttl-seconds", 0)),
    }
    for opt in ("src-prefix", "dst-prefix", "src-port", "dst-port", "comment"):
        if rule.get(opt) is not None:
            fields[opt] = str(rule[opt])
    r.hset(key, mapping=fields)
    log.info("ConfigDB wrote %s", key)


def _delete_configdb(r: redis.Redis, rule_id: str) -> None:
    r.delete(f"{TABLE_PREFIX}|{rule_id}")
    log.info("ConfigDB deleted %s|%s", TABLE_PREFIX, rule_id)


def _read_configdb_rule(r: redis.Redis, rule_id: str) -> Optional[dict]:
    raw = r.hgetall(f"{TABLE_PREFIX}|{rule_id}")
    if not raw:
        return None
    return {k.decode(): v.decode() for k, v in raw.items()}


def _snapshot_db(snap: redis.Redis, rule_id: str, rule: Optional[dict]) -> None:
    key = f"NOS_BRIDGE_SNAPSHOT|{rule_id}"
    if rule is None:
        snap.delete(key)
    else:
        snap.hset(key, mapping=rule)
        snap.expire(key, 86400)

# ---------------------------------------------------------------------------
# Auth / RBAC
# ---------------------------------------------------------------------------

def _peer_ou(context: grpc.ServicerContext) -> Optional[str]:
    """Extract OU from the peer's mTLS client certificate."""
    auth = context.auth_context()
    pem_list = auth.get("x509_pem_cert", [])
    if not pem_list:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem_list[0], default_backend())
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
        return attrs[0].value if attrs else None
    except Exception as e:
        log.warning("Failed to parse peer cert: %s", e)
        return None


def _ou_to_role(ou: Optional[str]) -> str:
    if ou in ("internal", "sdnc"):
        return "ADMIN"
    if ou == "aws":
        return "OPERATOR"
    if ou == "auto":
        return "AGENT"
    return "DENY"

# ---------------------------------------------------------------------------
# gNMI path / value helpers
# ---------------------------------------------------------------------------

def _extract_rule_id(path: gnmi_pb2.Path) -> Optional[str]:
    """Return rule-id from path elem[-1] key if this is a nos-iptables rule path."""
    for elem in path.elem:
        if elem.name == "rule" and "rule-id" in elem.key:
            return elem.key["rule-id"]
    return None


def _extract_json(val: gnmi_pb2.TypedValue) -> dict:
    which = val.WhichOneof("value")
    if which in ("json_ietf_val", "json_val"):
        raw = val.json_ietf_val if which == "json_ietf_val" else val.json_val
        return json.loads(raw)
    raise ValueError(f"Unsupported TypedValue type: {which}")


def _rule_to_typed_value(rule: dict) -> gnmi_pb2.TypedValue:
    return gnmi_pb2.TypedValue(json_ietf_val=json.dumps(rule).encode())

# ---------------------------------------------------------------------------
# gNMI servicer
# ---------------------------------------------------------------------------

class NosAclBridgeServicer(gnmi_pb2_grpc.gNMIServicer):

    def __init__(self, configdb: redis.Redis, snapshot: redis.Redis):
        self._db = configdb
        self._snap = snapshot

    # ------------------------------------------------------------------
    # Capabilities — advertise nos-iptables YANG model
    # ------------------------------------------------------------------
    def Capabilities(self, request, context):
        model = gnmi_pb2.ModelData(
            name="nos-iptables",
            organization="3S-NOS Secure Framework",
            version="2026-04-26",
        )
        return gnmi_pb2.CapabilityResponse(
            supported_models=[model],
            supported_encodings=[gnmi_pb2.JSON_IETF, gnmi_pb2.JSON],
            gNMI_version="0.7.0",
        )

    # ------------------------------------------------------------------
    # Get — read rule(s) from ConfigDB
    # ------------------------------------------------------------------
    def Get(self, request, context):
        ou = _peer_ou(context)
        role = _ou_to_role(ou)
        if role == "DENY":
            context.abort(grpc.StatusCode.PERMISSION_DENIED, f"cert OU {ou!r} not authorized")
            return

        notifications = []
        ts = int(time.time() * 1e9)

        for path in request.path:
            rule_id = _extract_rule_id(path)
            if rule_id:
                rule = _read_configdb_rule(self._db, rule_id)
                if rule is None:
                    context.abort(grpc.StatusCode.NOT_FOUND, f"rule-id {rule_id!r} not found")
                    return
                updates = [gnmi_pb2.Update(path=path, val=_rule_to_typed_value(rule))]
            else:
                # No specific rule-id → return all rules
                updates = []
                for raw_key in self._db.keys(f"{TABLE_PREFIX}|*".encode()):
                    rid = raw_key.decode().split("|", 1)[1]
                    rule = _read_configdb_rule(self._db, rid)
                    if rule:
                        rule["rule-id"] = rid
                        p = gnmi_pb2.Path(elem=[
                            gnmi_pb2.PathElem(name="nos-iptables"),
                            gnmi_pb2.PathElem(name="rule", key={"rule-id": rid}),
                        ])
                        updates.append(gnmi_pb2.Update(path=p, val=_rule_to_typed_value(rule)))

            notifications.append(gnmi_pb2.Notification(timestamp=ts, update=updates))

        log.info("Get from OU=%s role=%s: %d paths", ou, role, len(request.path))
        return gnmi_pb2.GetResponse(notification=notifications)

    # ------------------------------------------------------------------
    # Set — validate → ConfigDB → iptables
    # ------------------------------------------------------------------
    def Set(self, request, context):
        ou = _peer_ou(context)
        role = _ou_to_role(ou)
        if role == "DENY":
            context.abort(grpc.StatusCode.PERMISSION_DENIED, f"cert OU {ou!r} not authorized")
            return

        results = []
        ts = int(time.time() * 1e9)

        # Process deletes first
        for path in request.delete:
            rule_id = _extract_rule_id(path)
            if not rule_id:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "delete path must include rule-id key")
                return
            existing = _read_configdb_rule(self._db, rule_id)
            chain = (existing or {}).get("chain", "FORWARD")
            _delete_configdb(self._db, rule_id)
            remove_rule(rule_id, chain)
            _snapshot_db(self._snap, rule_id, None)
            log.info("Set DELETE rule=%s by OU=%s role=%s", rule_id, ou, role)
            results.append(gnmi_pb2.UpdateResult(
                path=path,
                op=gnmi_pb2.UpdateResult.DELETE,
            ))

        # Process updates and replaces (same semantics for iptables)
        for update in list(request.update) + list(request.replace):
            rule_id = _extract_rule_id(update.path)
            if not rule_id:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "update path must include rule-id key")
                return

            try:
                body = _extract_json(update.val)
            except (ValueError, json.JSONDecodeError) as e:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"invalid JSON val: {e}")
                return

            # Merge rule-id from path into body
            rule = {"rule-id": rule_id, **body}
            # Strip any module-prefixed wrapper (e.g. "nos-iptables:rule": {...})
            for k in list(rule.keys()):
                if ":" in k:
                    inner = rule.pop(k)
                    if isinstance(inner, dict):
                        rule.update(inner)
            # Normalize YANG field names to internal names
            if "src-ip" in rule and "src-prefix" not in rule:
                rule["src-prefix"] = rule.pop("src-ip")
            if "dst-ip" in rule and "dst-prefix" not in rule:
                rule["dst-prefix"] = rule.pop("dst-ip")

            try:
                validate_rule(rule)
                enforce_rbac(rule, role)
            except ValidationError as e:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
                return

            # Remove old iptables entry if exists (replace semantics)
            existing = _read_configdb_rule(self._db, rule_id)
            if existing:
                remove_rule(rule_id, existing.get("chain", "FORWARD"))

            _write_configdb(self._db, rule)
            apply_rule(rule)
            _snapshot_db(self._snap, rule_id, {**rule, "role": role, "ou": ou or ""})
            log.info("Set UPDATE rule=%s action=%s src=%s by OU=%s role=%s",
                     rule_id, rule.get("action"), rule.get("src-prefix", "*"), ou, role)

            results.append(gnmi_pb2.UpdateResult(
                path=update.path,
                op=gnmi_pb2.UpdateResult.UPDATE,
            ))

        return gnmi_pb2.SetResponse(prefix=request.prefix, response=results, timestamp=ts)

    # ------------------------------------------------------------------
    # Subscribe — not implemented in W1
    # ------------------------------------------------------------------
    def Subscribe(self, request_iterator, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "Subscribe not implemented in nos-acl-bridge W1")

# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------

def _load_tls_creds() -> grpc.ServerCredentials:
    cert_file = os.path.join(CERTS_DIR, "server.crt")
    key_file  = os.path.join(CERTS_DIR, "server.key")
    ca_file   = os.path.join(CERTS_DIR, "trustedCertificates.crt")

    for f in (cert_file, key_file, ca_file):
        if not os.path.exists(f):
            log.error("Missing cert file: %s", f)
            sys.exit(1)

    with open(cert_file, "rb") as f: cert = f.read()
    with open(key_file,  "rb") as f: key  = f.read()
    with open(ca_file,   "rb") as f: ca   = f.read()

    return grpc.ssl_server_credentials(
        [(key, cert)],
        root_certificates=ca,
        require_client_auth=True,
    )


def main() -> None:
    log.info("nos-acl-bridge starting — port %d, certs %s", BRIDGE_PORT, CERTS_DIR)

    configdb = _open_redis(CONFIGDB_ID)
    snapshot = _open_redis(SNAPSHOT_DB_ID)

    try:
        configdb.ping()
    except redis.exceptions.ConnectionError as e:
        log.error("Cannot connect to Redis: %s", e)
        sys.exit(1)

    log.info("Ensuring base iptables rules...")
    ensure_base_rules()
    log.info("Running startup reconcile...")
    reconcile_on_startup(configdb)

    creds = _load_tls_creds()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    gnmi_pb2_grpc.add_gNMIServicer_to_server(NosAclBridgeServicer(configdb, snapshot), server)
    server.add_secure_port(f"[::]:{BRIDGE_PORT}", creds)
    server.start()
    log.info("nos-acl-bridge listening on :%d", BRIDGE_PORT)

    def _shutdown(sig, _frame):
        log.info("Signal %d received — shutting down", sig)
        server.stop(grace=5)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
