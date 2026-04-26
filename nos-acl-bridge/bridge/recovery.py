from __future__ import annotations

"""Startup reconciliation: ConfigDB DB 4 (authoritative) ↔ iptables FORWARD chain.

Called once at bridge startup before the gNMI server begins accepting connections.

Algorithm:
  1. Read all NOS_IPTABLES_RULE|* keys from ConfigDB (DB 4).
  2. Read all iptables rules tagged with 'nos:<rule-id>' comments.
  3. Apply rules that are in Redis but missing from iptables.
  4. Remove iptables rules tagged 'nos:*' that have no matching Redis entry (orphans).
  5. Field drift (rule exists in both but iptables state differs) → remove + re-apply.
     Drift detection is best-effort: we compare the chain stored in Redis vs what
     iptables reports. Full-field comparison would require parsing iptables output
     in detail — sufficient for thesis demo scope.
"""
import logging

import redis

from iptables import apply_rule, list_nos_rules, remove_rule

log = logging.getLogger("nos-acl-bridge.recovery")

CONFIGDB_ID = 4
TABLE_PREFIX = "NOS_IPTABLES_RULE"


def _read_redis_rules(r: redis.Redis) -> dict[str, dict]:
    """Return {rule-id: {field: value}} from ConfigDB NOS_IPTABLES_RULE table."""
    rules: dict[str, dict] = {}
    pattern = f"{TABLE_PREFIX}|*".encode()
    for raw_key in r.keys(pattern):
        key = raw_key.decode()
        rule_id = key.split("|", 1)[1]
        raw = r.hgetall(raw_key)
        rules[rule_id] = {k.decode(): v.decode() for k, v in raw.items()}
    return rules


def reconcile_on_startup(configdb: redis.Redis) -> None:
    """Diff ConfigDB ↔ iptables and bring iptables in sync.

    Designed to be idempotent — safe to call multiple times.
    """
    redis_rules = _read_redis_rules(configdb)
    ipt_rules = list_nos_rules()  # {rule-id: chain}

    redis_ids = set(redis_rules)
    ipt_ids = set(ipt_rules)

    applied = 0
    removed = 0
    replaced = 0

    # In Redis but not in iptables → apply
    for rule_id in redis_ids - ipt_ids:
        rule = {**redis_rules[rule_id], "rule-id": rule_id}
        log.info("Reconcile APPLY: %s", rule_id)
        try:
            apply_rule(rule)
            applied += 1
        except Exception as e:
            log.error("Reconcile apply failed for %s: %s", rule_id, e)

    # In iptables but not in Redis → orphan, remove
    for rule_id in ipt_ids - redis_ids:
        chain = ipt_rules[rule_id]
        log.warning("Reconcile REMOVE orphan: %s (chain=%s)", rule_id, chain)
        try:
            remove_rule(rule_id, chain)
            removed += 1
        except Exception as e:
            log.error("Reconcile remove failed for %s: %s", rule_id, e)

    # In both — check chain drift
    for rule_id in redis_ids & ipt_ids:
        redis_chain = redis_rules[rule_id].get("chain", "FORWARD")
        ipt_chain = ipt_rules[rule_id]
        if redis_chain != ipt_chain:
            log.warning(
                "Reconcile REPLACE (chain drift): %s redis=%s iptables=%s",
                rule_id, redis_chain, ipt_chain,
            )
            try:
                remove_rule(rule_id, ipt_chain)
                rule = {**redis_rules[rule_id], "rule-id": rule_id}
                apply_rule(rule)
                replaced += 1
            except Exception as e:
                log.error("Reconcile replace failed for %s: %s", rule_id, e)

    log.info(
        "Reconcile complete: %d applied, %d removed, %d replaced",
        applied, removed, replaced,
    )
