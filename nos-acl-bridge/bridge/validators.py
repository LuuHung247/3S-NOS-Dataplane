"""Schema validation for nos-iptables YANG rules.

Implements the constraints from 3snos-iptables.yang manually (no pyangbind).
All public functions raise ValidationError on bad input.
"""
import ipaddress
import re

_RULE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")
_VALID_CHAINS = {"FORWARD", "INPUT", "OUTPUT"}
_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "sctp", "all"}
_PORT_PROTOCOLS = {"tcp", "udp", "sctp"}
_VALID_ACTIONS = {"DROP", "ACCEPT", "REJECT"}
_VALID_SOURCES = {"sdnc", "agent", "manual"}


class ValidationError(Exception):
    pass


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValidationError(msg)


def validate_rule(rule: dict) -> None:
    """Validate a rule dict against nos-iptables.yang constraints.

    Raises ValidationError if any constraint is violated.
    """
    # rule-id: mandatory, pattern [a-zA-Z0-9_-]+, length 1..128
    rule_id = rule.get("rule-id", "")
    _require(bool(_RULE_ID_RE.match(rule_id)), f"rule-id invalid: {rule_id!r}")

    # chain: enum FORWARD|INPUT|OUTPUT, default FORWARD
    chain = rule.get("chain", "FORWARD")
    _require(chain in _VALID_CHAINS, f"chain must be one of {_VALID_CHAINS}, got {chain!r}")

    # src-prefix / dst-prefix: inet:ipv4-prefix (optional)
    for leaf in ("src-prefix", "dst-prefix"):
        val = rule.get(leaf)
        if val is not None:
            try:
                ipaddress.IPv4Network(val, strict=False)
            except ValueError:
                raise ValidationError(f"{leaf} is not a valid IPv4 prefix: {val!r}")

    # protocol: enum, default all
    proto = rule.get("protocol", "all")
    _require(proto in _VALID_PROTOCOLS, f"protocol must be one of {_VALID_PROTOCOLS}, got {proto!r}")

    # src-port / dst-port: uint16 1..65535, when clause: only tcp/udp/sctp
    for leaf in ("src-port", "dst-port"):
        val = rule.get(leaf)
        if val is not None:
            _require(
                proto in _PORT_PROTOCOLS,
                f"{leaf} is only valid for tcp/udp/sctp (got protocol={proto!r})",
            )
            try:
                port = int(val)
            except (TypeError, ValueError):
                raise ValidationError(f"{leaf} must be an integer, got {val!r}")
            _require(1 <= port <= 65535, f"{leaf} out of range 1-65535: {port}")

    # action: mandatory enum DROP|ACCEPT|REJECT
    action = rule.get("action")
    _require(action is not None, "action is mandatory")
    _require(action in _VALID_ACTIONS, f"action must be one of {_VALID_ACTIONS}, got {action!r}")

    # priority: uint16 1..9999, default 1000
    try:
        priority = int(rule.get("priority", 1000))
    except (TypeError, ValueError):
        raise ValidationError(f"priority must be an integer, got {rule.get('priority')!r}")
    _require(1 <= priority <= 9999, f"priority out of range 1-9999: {priority}")

    # source: enum sdnc|agent|manual, default sdnc
    source = rule.get("source", "sdnc")
    _require(source in _VALID_SOURCES, f"source must be one of {_VALID_SOURCES}, got {source!r}")

    # comment: string length 0..256 (optional)
    comment = rule.get("comment", "")
    if comment:
        _require(len(comment) <= 256, f"comment exceeds 256 chars (got {len(comment)})")

    # ttl-seconds: uint32 0..86400, default 0
    try:
        ttl = int(rule.get("ttl-seconds", 0))
    except (TypeError, ValueError):
        raise ValidationError(f"ttl-seconds must be an integer, got {rule.get('ttl-seconds')!r}")
    _require(0 <= ttl <= 86400, f"ttl-seconds out of range 0-86400: {ttl}")

    # RBAC / AGENT constraint: agent rules MUST have action=DROP
    if source == "agent":
        _require(action == "DROP", "AGENT (agent source) rules must have action=DROP")


def enforce_rbac(rule: dict, role: str) -> None:
    """Enforce per-role source constraints.

    ADMIN (internal/sdnc cert OU): no restrictions.
    OPERATOR (aws cert OU): may only push source=sdnc rules.
    AGENT (auto cert OU): may only push source=agent rules (action=DROP enforced by validate_rule).
    """
    source = rule.get("source", "sdnc")
    if role == "ADMIN":
        return
    if role == "OPERATOR":
        _require(source == "sdnc", f"OPERATOR role may only push source=sdnc, got {source!r}")
    elif role == "AGENT":
        _require(source == "agent", f"AGENT role may only push source=agent, got {source!r}")
    else:
        raise ValidationError(f"Unknown role {role!r} — access denied")
