"""
analysis.py
===========

Deterministic checks against normalized rules (see normalizer.py). Nothing
in this module calls an LLM -- rule-overlap math is exact, testable logic,
and it should stay that way. The AI risk-narrative layer (not implemented
in this phase) consumes the `findings` this module produces; it never
re-derives them.

Assumes the input rule list is already in evaluation order (pre-rulebase,
then post-rulebase, in the order Panorama would apply them) for a single
device group. Call these functions once per device group.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Superset / containment primitives
# --------------------------------------------------------------------------

def _parse_cidr(value: str) -> Optional[ipaddress._BaseNetwork]:
    """Returns an ip_network for plain CIDR/host strings, or None for
    anything this pipeline can't reason about numerically (ranges, fqdns,
    unresolved refs, dynamic groups) -- those fall back to exact-match logic.
    """
    if value.startswith(("range:", "fqdn:", "unresolved:", "dynamic-unresolved:", "unknown-address-type:")):
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def addresses_superset(earlier: List[str], later: List[str]) -> bool:
    """True if every address `later` could match is already covered by `earlier`."""
    if "any" in earlier:
        return True
    if "any" in later:
        return False  # later matches everything; earlier (not "any") can't cover that

    earlier_nets = [n for n in (_parse_cidr(x) for x in earlier) if n is not None]

    for value in later:
        net = _parse_cidr(value)
        if net is None:
            # Can't do numeric containment (range/fqdn/unresolved) -- require
            # a literal match in `earlier` or treat as not covered.
            if value not in earlier:
                return False
            continue
        if not any(_network_contains(en, net) for en in earlier_nets):
            return False
    return True


def _network_contains(outer, inner) -> bool:
    if outer.version != inner.version:
        return False
    try:
        return inner.subnet_of(outer)
    except TypeError:
        return False


def zones_superset(earlier: List[str], later: List[str]) -> bool:
    if "any" in earlier:
        return True
    return set(later) <= set(earlier)


def apps_superset(earlier: List[str], later: List[str]) -> bool:
    if "any" in earlier:
        return True
    return set(later) <= set(earlier)


def _parse_service(value: str) -> Tuple[str, Optional[int], Optional[int]]:
    """'tcp/443' -> ('tcp', 443, 443); 'tcp/1-1024' -> ('tcp', 1, 1024);
    'any' / 'application-default' -> (value, None, None) sentinel.
    """
    if value in ("any", "application-default"):
        return (value, None, None)
    if "/" not in value:
        return (value, None, None)  # unrecognized format, treated conservatively
    proto, port = value.split("/", 1)
    if port == "any":
        return (proto, 1, 65535)
    if "-" in port:
        lo, hi = port.split("-", 1)
        try:
            return (proto, int(lo), int(hi))
        except ValueError:
            return (proto, None, None)
    try:
        p = int(port)
        return (proto, p, p)
    except ValueError:
        return (proto, None, None)


def services_superset(earlier: List[str], later: List[str]) -> bool:
    if "any" in earlier:
        return True
    if "any" in later:
        return False

    for lval in later:
        lproto, llo, lhi = _parse_service(lval)
        if lproto == "application-default":
            if "application-default" not in earlier:
                return False
            continue
        if llo is None:
            if lval not in earlier:
                return False
            continue

        covered = False
        for eval_ in earlier:
            eproto, elo, ehi = _parse_service(eval_)
            if eproto == "application-default":
                continue
            if elo is None:
                continue
            if eproto == lproto and elo <= llo and ehi >= lhi:
                covered = True
                break
        if not covered:
            return False
    return True


def rule_is_superset(earlier: dict, later: dict) -> bool:
    """True if `earlier` would match every packet `later` would match."""
    return (
        zones_superset(earlier["source_zones"], later["source_zones"])
        and zones_superset(earlier["destination_zones"], later["destination_zones"])
        and addresses_superset(earlier["source_addresses"], later["source_addresses"])
        and addresses_superset(earlier["destination_addresses"], later["destination_addresses"])
        and services_superset(earlier["services"], later["services"])
        and apps_superset(earlier["applications"], later["applications"])
    )


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    finding_type: str          # "shadowed" | "redundant" | "overly_permissive" | "hygiene"
    severity: str              # "high" | "medium" | "low"
    rule_name: str
    device_group: str
    detail: str
    related_rule: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "rule_name": self.rule_name,
            "device_group": self.device_group,
            "detail": self.detail,
            "related_rule": self.related_rule,
        }


def find_shadowed_rules(rules: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    for i, rule in enumerate(rules):
        if rule["disabled"]:
            continue
        for earlier in rules[:i]:
            if earlier["disabled"]:
                continue
            if rule_is_superset(earlier, rule):
                findings.append(Finding(
                    finding_type="shadowed",
                    severity="high",
                    rule_name=rule["rule_name"],
                    device_group=rule["device_group"],
                    related_rule=earlier["rule_name"],
                    detail=(
                        f"Rule {rule['rule_name']!r} at position {rule['position']} is fully "
                        f"shadowed by earlier rule {earlier['rule_name']!r} at position "
                        f"{earlier['position']} -- traffic matching {rule['rule_name']!r} "
                        f"will never reach it."
                    ),
                ))
                break  # one shadowing rule is enough to report
    return findings


def _canonical_key(rule: dict) -> tuple:
    return (
        tuple(sorted(rule["source_zones"])),
        tuple(sorted(rule["destination_zones"])),
        tuple(sorted(rule["source_addresses"])),
        tuple(sorted(rule["destination_addresses"])),
        tuple(sorted(rule["services"])),
        tuple(sorted(rule["applications"])),
        rule["action"],
    )


def find_redundant_rules(rules: List[dict]) -> List[Finding]:
    """Flags rules with identical match criteria AND identical action to an
    earlier rule. This is distinct from shadowing: neither rule is
    unreachable (they behave the same either way), but one is unnecessary.
    """
    findings: List[Finding] = []
    seen: Dict[tuple, str] = {}
    for rule in rules:
        if rule["disabled"]:
            continue
        key = _canonical_key(rule)
        if key in seen:
            findings.append(Finding(
                finding_type="redundant",
                severity="low",
                rule_name=rule["rule_name"],
                device_group=rule["device_group"],
                related_rule=seen[key],
                detail=(
                    f"Rule {rule['rule_name']!r} has identical match criteria and action "
                    f"to {seen[key]!r}. Consider consolidating."
                ),
            ))
        else:
            seen[key] = rule["rule_name"]
    return findings


def find_overly_permissive_rules(rules: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules:
        if rule["disabled"] or rule["action"] != "allow":
            continue
        reasons: List[str] = []
        src_any = "any" in rule["source_addresses"]
        dst_any = "any" in rule["destination_addresses"]
        svc_any = "any" in rule["services"]
        app_any = "any" in rule["applications"]
        no_log = not rule["log_forwarding_profile"]

        if src_any and dst_any:
            reasons.append('source and destination addresses are both "any"')
        elif dst_any:
            reasons.append('destination address is "any"')
        if svc_any:
            reasons.append('service is "any" (all ports, all protocols)')
        if app_any:
            reasons.append('application is "any" (not App-ID scoped)')
        if no_log:
            reasons.append("no log-forwarding profile attached")

        if not reasons:
            continue

        # Simple, explainable severity scoring -- not a black box.
        high_risk_combo = (src_any or dst_any) and (svc_any or app_any)
        if high_risk_combo:
            severity = "high"
        elif len(reasons) >= 2:
            severity = "medium"
        else:
            severity = "low"

        findings.append(Finding(
            finding_type="overly_permissive",
            severity=severity,
            rule_name=rule["rule_name"],
            device_group=rule["device_group"],
            detail="Allow rule is broader than necessary: " + "; ".join(reasons) + ".",
        ))
    return findings


def find_hygiene_issues(rules: List[dict], unresolved_warnings: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules:
        if rule["disabled"]:
            findings.append(Finding(
                finding_type="hygiene",
                severity="low",
                rule_name=rule["rule_name"],
                device_group=rule["device_group"],
                detail="Rule is disabled. If it's no longer needed, remove it during the next cleanup window.",
            ))
        stale_refs = [
            v for v in rule["source_addresses"] + rule["destination_addresses"] + rule["services"]
            if v.startswith("unresolved:")
        ]
        if stale_refs:
            findings.append(Finding(
                finding_type="hygiene",
                severity="medium",
                rule_name=rule["rule_name"],
                device_group=rule["device_group"],
                detail=f"Rule references object(s) that could not be resolved: {', '.join(stale_refs)}.",
            ))
        dynamic_refs = [
            v for v in rule["source_addresses"] + rule["destination_addresses"]
            if v.startswith("dynamic-unresolved:")
        ]
        if dynamic_refs:
            findings.append(Finding(
                finding_type="hygiene",
                severity="low",
                rule_name=rule["rule_name"],
                device_group=rule["device_group"],
                detail=(
                    "Rule includes a dynamic (tag-based) address group, which this pipeline "
                    "cannot statically resolve -- review its tag filter and current membership manually."
                ),
            ))
    return findings


def analyze(rules: List[dict]) -> List[Finding]:
    """Runs all deterministic checks for a single device group's rule list
    (already in evaluation order) and returns the combined findings.
    """
    findings: List[Finding] = []
    findings.extend(find_shadowed_rules(rules))
    findings.extend(find_redundant_rules(rules))
    findings.extend(find_overly_permissive_rules(rules))
    findings.extend(find_hygiene_issues(rules))
    return findings
