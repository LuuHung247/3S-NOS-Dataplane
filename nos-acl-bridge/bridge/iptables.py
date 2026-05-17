from __future__ import annotations

"""iptables FORWARD-chain operations for nos-acl-bridge.

Rules are tagged with -m comment --comment 'nos:<rule-id>' so the bridge
can identify and reconcile them across restarts.
"""
import re
import subprocess
import logging

log = logging.getLogger("nos-acl-bridge.iptables")

# Matches 'nos:<rule-id>' in iptables --list output
_NOS_RE = re.compile(r"nos:([a-zA-Z0-9_\-]+)")

# Protocols that support port matching
_PORT_PROTOCOLS = {"tcp", "udp", "sctp"}


def _build_cmd(rule: dict) -> list[str]:
    """Return the iptables command list for a rule dict (without -I/-A position yet)."""
    chain = rule.get("chain", "FORWARD")
    priority = int(rule.get("priority", 1000))

    if priority < 100:
        pos_args = ["-I", chain, "1"]
    elif priority < 1000:
        pos_args = ["-I", chain, "2"]
    else:
        pos_args = ["-A", chain]

    cmd = ["iptables"] + pos_args

    if rule.get("src-prefix"):
        cmd += ["-s", rule["src-prefix"]]
    if rule.get("dst-prefix"):
        cmd += ["-d", rule["dst-prefix"]]

    proto = rule.get("protocol", "all")
    if proto != "all":
        cmd += ["-p", proto]
        if rule.get("src-port"):
            cmd += ["--sport", str(rule["src-port"])]
        if rule.get("dst-port"):
            cmd += ["--dport", str(rule["dst-port"])]

    rule_id = rule["rule-id"]
    comment = f"nos:{rule_id}"
    if rule.get("comment"):
        comment += f" {rule['comment']}"
    cmd += ["-m", "comment", "--comment", comment, "-j", rule["action"]]
    return cmd


def apply_rule(rule: dict) -> None:
    """Insert/append an iptables rule from a rule dict."""
    cmd = _build_cmd(rule)
    log.info("iptables apply: %s", " ".join(cmd))
    subprocess.run(cmd, check=True)


def remove_rule(rule_id: str, chain: str = "FORWARD") -> None:
    """Delete all iptables rules tagged nos:<rule-id> from chain."""
    try:
        out = subprocess.check_output(
            ["iptables", "-L", chain, "-n", "--line-numbers"], text=True
        )
    except subprocess.CalledProcessError as e:
        log.error("iptables list failed: %s", e)
        return

    nums = []
    for line in out.splitlines():
        if f"nos:{rule_id}" in line:
            tok = line.split()
            if tok and tok[0].isdigit():
                nums.append(int(tok[0]))

    for num in sorted(nums, reverse=True):
        try:
            subprocess.run(["iptables", "-D", chain, str(num)], check=True)
            log.info("iptables removed rule %s at position %d in %s", rule_id, num, chain)
        except subprocess.CalledProcessError as e:
            log.error("iptables delete failed: %s", e)


def ensure_base_rules(chain: str = "FORWARD") -> None:
    """Ensure infrastructure base rules exist in chain.

    ESTABLISHED,RELATED must always be present so reply traffic for
    any SF-authorized flow works correctly. This is enforcement-layer
    infrastructure, not a policy rule — not stored in ConfigDB or YANG.

    Idempotent: checks before inserting, safe to call on every startup.
    """
    try:
        out = subprocess.check_output(
            ["iptables", "-L", chain, "-n"], text=True
        )
    except subprocess.CalledProcessError as e:
        log.error("iptables list failed in ensure_base_rules: %s", e)
        return

    if "ctstate RELATED,ESTABLISHED" in out or "state RELATED,ESTABLISHED" in out:
        log.info("Base rule ESTABLISHED,RELATED already present in %s", chain)
        return

    cmd = [
        "iptables", "-A", chain,
        "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
        "-j", "ACCEPT",
    ]
    try:
        subprocess.run(cmd, check=True)
        log.info("Base rule ESTABLISHED,RELATED inserted into %s", chain)
    except subprocess.CalledProcessError as e:
        log.error("Failed to insert ESTABLISHED,RELATED base rule: %s", e)


def list_nos_rules() -> dict[str, str]:
    """Return {rule-id: chain} for all iptables rules tagged with 'nos:'."""
    result: dict[str, str] = {}
    try:
        out = subprocess.check_output(
            ["iptables", "-L", "-n", "--line-numbers", "-v"], text=True
        )
    except subprocess.CalledProcessError as e:
        log.error("iptables list all failed: %s", e)
        return result

    current_chain = "FORWARD"
    for line in out.splitlines():
        if line.startswith("Chain "):
            current_chain = line.split()[1]
        m = _NOS_RE.search(line)
        if m:
            result[m.group(1)] = current_chain
    return result
