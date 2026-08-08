"""
normalizer.py
=============

Turns raw Panorama XML (rulebase + address/service/application objects) into
a flat list of self-contained rule dicts. Downstream stages (analysis.py)
should never need to look at XML or chase an object reference -- everything
is resolved here, once.

Design choices worth calling out:
  - Literal "any" is preserved as the string "any", never expanded to
    0.0.0.0/0. The analysis engine treats explicit "any" as a distinct,
    higher-severity signal than "resolves to a very large range".
  - Address/service GROUP resolution is recursive with cycle detection --
    a misconfigured group that references itself (directly or via another
    group) raises a ResolutionError rather than looping forever.
  - Dynamic address groups (tag-based membership) can't be resolved
    statically from config alone; they're marked as
    {"type": "dynamic-unresolved", "filter": "..."} so the analysis engine
    can flag them for manual review instead of silently mis-evaluating them.
  - Unknown/missing references (a rule points at an object that was deleted)
    are recorded in `warnings` rather than raising, so one bad reference
    doesn't kill the whole run.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


class ResolutionError(Exception):
    """Raised for unrecoverable resolution problems, e.g. a reference cycle."""


def _members(entry: ET.Element, tag: str) -> List[str]:
    """Extract <tag><member>x</member><member>y</member></tag> as a list of strings."""
    container = entry.find(tag)
    if container is None:
        return []
    return [m.text for m in container.findall("member") if m.text]


def _text(entry: ET.Element, tag: str, default: Optional[str] = None) -> Optional[str]:
    el = entry.find(tag)
    return el.text if el is not None and el.text is not None else default


@dataclass
class ObjectIndex:
    """Resolved address or service objects/groups: name -> list of leaf values."""
    resolved: Dict[str, List[str]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


def build_address_index(address_entries: List[ET.Element], group_entries: List[ET.Element]) -> ObjectIndex:
    # Leaf objects first: name -> single-element list
    leaves: Dict[str, List[str]] = {}
    for entry in address_entries:
        name = entry.attrib.get("name")
        if not name:
            continue
        if (v := _text(entry, "ip-netmask")) is not None:
            leaves[name] = [v]
        elif (v := _text(entry, "ip-range")) is not None:
            leaves[name] = [f"range:{v}"]
        elif (v := _text(entry, "fqdn")) is not None:
            leaves[name] = [f"fqdn:{v}"]
        else:
            leaves[name] = [f"unknown-address-type:{name}"]

    # Group definitions: name -> list of member names (static) or a dynamic marker
    group_members: Dict[str, List[str]] = {}
    dynamic_groups: Dict[str, str] = {}
    for entry in group_entries:
        name = entry.attrib.get("name")
        if not name:
            continue
        dyn = entry.find("dynamic")
        if dyn is not None:
            filt = _text(dyn, "filter", default="")
            dynamic_groups[name] = filt
        else:
            group_members[name] = _members(entry, "static")

    index = ObjectIndex()

    def resolve(name: str, stack: Set[str]) -> List[str]:
        if name == "any":
            return ["any"]
        if name in dynamic_groups:
            return [f"dynamic-unresolved:{dynamic_groups[name]}"]
        if name in leaves:
            return leaves[name]
        if name in group_members:
            if name in stack:
                raise ResolutionError(
                    f"Address group reference cycle detected involving {name!r} "
                    f"(path: {' -> '.join(stack)} -> {name})"
                )
            stack = stack | {name}
            result: List[str] = []
            for member in group_members[name]:
                result.extend(resolve(member, stack))
            return result
        index.warnings.append(f"Unresolved address reference: {name!r} (object not found)")
        return [f"unresolved:{name}"]

    for name in list(leaves) + list(group_members) + list(dynamic_groups):
        index.resolved[name] = resolve(name, set())

    return index


def build_service_index(service_entries: List[ET.Element], group_entries: List[ET.Element]) -> ObjectIndex:
    leaves: Dict[str, List[str]] = {}
    for entry in service_entries:
        name = entry.attrib.get("name")
        if not name:
            continue
        proto = entry.find("protocol")
        parts: List[str] = []
        if proto is not None:
            for proto_name in ("tcp", "udp"):
                proto_el = proto.find(proto_name)
                if proto_el is not None:
                    port = _text(proto_el, "port", default="any")
                    parts.append(f"{proto_name}/{port}")
        leaves[name] = parts or [f"unknown-service-type:{name}"]

    group_members: Dict[str, List[str]] = {}
    for entry in group_entries:
        name = entry.attrib.get("name")
        if not name:
            continue
        group_members[name] = _members(entry, "members")

    index = ObjectIndex()

    def resolve(name: str, stack: Set[str]) -> List[str]:
        if name in ("any", "application-default"):
            return [name]
        if name in leaves:
            return leaves[name]
        if name in group_members:
            if name in stack:
                raise ResolutionError(
                    f"Service group reference cycle detected involving {name!r} "
                    f"(path: {' -> '.join(stack)} -> {name})"
                )
            stack = stack | {name}
            result: List[str] = []
            for member in group_members[name]:
                result.extend(resolve(member, stack))
            return result
        index.warnings.append(f"Unresolved service reference: {name!r} (object not found)")
        return [f"unresolved:{name}"]

    for name in list(leaves) + list(group_members):
        index.resolved[name] = resolve(name, set())

    return index


def _resolve_refs(names: List[str], index: ObjectIndex) -> List[str]:
    out: List[str] = []
    for name in names:
        if name == "any":
            out.append("any")
        elif name in index.resolved:
            out.extend(index.resolved[name])
        else:
            index.warnings.append(f"Unresolved reference in rule: {name!r}")
            out.append(f"unresolved:{name}")
    # de-dupe while preserving order
    seen = set()
    deduped = []
    for v in out:
        if v not in seen:
            seen.add(v)
            deduped.append(v)
    return deduped


def parse_rulebase(
    rulebase_root: ET.Element,
    device_group: str,
    address_index: ObjectIndex,
    service_index: ObjectIndex,
) -> List[dict]:
    """Parse a <rules> element (from get_device_group_rulebase) into a flat
    list of normalized rule dicts, in rulebase order (position matters for
    shadowing analysis).
    """
    rules: List[dict] = []
    entries = rulebase_root.findall(".//entry")
    for position, entry in enumerate(entries):
        name = entry.attrib.get("name", f"unnamed-rule-{position}")
        source_raw = _members(entry, "source") or ["any"]
        dest_raw = _members(entry, "destination") or ["any"]
        service_raw = _members(entry, "service") or ["application-default"]
        apps_raw = _members(entry, "application") or ["any"]

        rule = {
            "rule_name": name,
            "device_group": device_group,
            "position": position,
            "disabled": (_text(entry, "disabled", default="no") == "yes"),
            "source_zones": _members(entry, "from") or ["any"],
            "destination_zones": _members(entry, "to") or ["any"],
            "source_addresses": _resolve_refs(source_raw, address_index),
            "destination_addresses": _resolve_refs(dest_raw, address_index),
            "applications": apps_raw,  # App-ID names are not expanded further
            "services": _resolve_refs(service_raw, service_index),
            "action": _text(entry, "action", default="allow"),
            "log_forwarding_profile": _text(entry, "log-setting"),
            "tags": _members(entry, "tag"),
        }
        rules.append(rule)
    return rules
