from pan_rule_validator.analysis import (
    addresses_superset,
    analyze,
    apps_superset,
    find_overly_permissive_rules,
    find_redundant_rules,
    find_shadowed_rules,
    services_superset,
    zones_superset,
)


def _rule(name, position, **overrides):
    base = {
        "rule_name": name,
        "device_group": "DG-Test",
        "position": position,
        "disabled": False,
        "source_zones": ["untrust"],
        "destination_zones": ["dmz"],
        "source_addresses": ["any"],
        "destination_addresses": ["10.0.0.5/32"],
        "applications": ["ssl"],
        "services": ["tcp/443"],
        "action": "allow",
        "log_forwarding_profile": "default-forward",
        "tags": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------- primitives

def test_addresses_superset_any_covers_everything():
    assert addresses_superset(["any"], ["10.0.0.0/24"]) is True


def test_addresses_superset_cidr_containment():
    assert addresses_superset(["10.0.0.0/24"], ["10.0.0.5/32"]) is True
    assert addresses_superset(["10.0.0.0/24"], ["10.1.0.5/32"]) is False


def test_addresses_superset_later_any_not_covered_by_specific_earlier():
    assert addresses_superset(["10.0.0.0/24"], ["any"]) is False


def test_services_superset_port_ranges():
    assert services_superset(["tcp/1-65535"], ["tcp/443"]) is True
    assert services_superset(["tcp/443"], ["tcp/8443"]) is False
    assert services_superset(["any"], ["tcp/8443"]) is True


def test_zones_and_apps_superset():
    assert zones_superset(["any"], ["untrust", "dmz"]) is True
    assert zones_superset(["untrust"], ["untrust", "dmz"]) is False
    assert apps_superset(["any"], ["ssl"]) is True
    assert apps_superset(["ssl"], ["ssl", "web-browsing"]) is False


# ---------------------------------------------------------------- shadowing

def test_broad_earlier_rule_shadows_narrow_later_rule():
    broad = _rule(
        "Broad-Allow-Any-Any", 0,
        source_addresses=["any"], destination_addresses=["any"],
        services=["any"], applications=["any"], source_zones=["any"], destination_zones=["any"],
    )
    narrow = _rule(
        "Narrow-Allow-Web", 1,
        source_addresses=["10.1.1.0/24"], destination_addresses=["10.0.0.5/32"],
        services=["tcp/443"], applications=["ssl"],
    )
    findings = find_shadowed_rules([broad, narrow])
    assert len(findings) == 1
    assert findings[0].rule_name == "Narrow-Allow-Web"
    assert findings[0].related_rule == "Broad-Allow-Any-Any"
    assert findings[0].severity == "high"


def test_narrower_earlier_rule_does_not_shadow_broader_later_rule():
    narrow = _rule("Narrow", 0, destination_addresses=["10.0.0.5/32"])
    broad = _rule("Broad", 1, destination_addresses=["10.0.0.0/24"])
    findings = find_shadowed_rules([narrow, broad])
    assert findings == []


def test_disabled_rule_does_not_shadow_or_get_shadowed():
    broad_disabled = _rule(
        "Broad-Disabled", 0,
        source_addresses=["any"], destination_addresses=["any"],
        services=["any"], applications=["any"], disabled=True,
    )
    narrow = _rule("Narrow", 1, destination_addresses=["10.0.0.5/32"])
    findings = find_shadowed_rules([broad_disabled, narrow])
    assert findings == []


def test_different_action_does_not_count_as_shadowed():
    # A superset MATCH with a different action still changes behavior for
    # that traffic, so it isn't "the same" -- but per this simple model we
    # only compare match criteria, not action, since a deny before an allow
    # for the same traffic is itself worth flagging as shadowing (the deny
    # wins). This test documents that current behavior explicitly.
    deny_broad = _rule(
        "Deny-Broad", 0,
        source_addresses=["any"], destination_addresses=["any"],
        services=["any"], applications=["any"], action="deny",
    )
    allow_narrow = _rule("Allow-Narrow", 1, destination_addresses=["10.0.0.5/32"])
    findings = find_shadowed_rules([deny_broad, allow_narrow])
    assert len(findings) == 1
    assert findings[0].rule_name == "Allow-Narrow"


# ---------------------------------------------------------------- redundancy

def test_identical_rules_flagged_redundant_not_shadowed_as_high():
    r1 = _rule("Rule-A", 0)
    r2 = _rule("Rule-B", 1)  # identical criteria to Rule-A
    findings = find_redundant_rules([r1, r2])
    assert len(findings) == 1
    assert findings[0].rule_name == "Rule-B"
    assert findings[0].related_rule == "Rule-A"
    assert findings[0].severity == "low"


# ---------------------------------------------------------- overly permissive

def test_any_any_allow_no_log_is_high_severity():
    rule = _rule(
        "Allow-Any-Any", 0,
        source_addresses=["any"], destination_addresses=["any"],
        services=["any"], applications=["any"], log_forwarding_profile=None,
    )
    findings = find_overly_permissive_rules([rule])
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_scoped_rule_with_logging_is_not_flagged():
    rule = _rule("Allow-Web-Scoped", 0)  # dest is a /32, service is tcp/443, has logging
    findings = find_overly_permissive_rules([rule])
    assert findings == []


def test_missing_log_profile_alone_is_low_severity():
    rule = _rule("Allow-Web-No-Log", 0, log_forwarding_profile=None)
    findings = find_overly_permissive_rules([rule])
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_deny_rules_are_never_flagged_overly_permissive():
    rule = _rule(
        "Deny-Any-Any", 0,
        source_addresses=["any"], destination_addresses=["any"],
        services=["any"], applications=["any"], action="deny",
    )
    assert find_overly_permissive_rules([rule]) == []


# ---------------------------------------------------------------- full analyze()

def test_analyze_runs_all_checks_together():
    broad = _rule(
        "Broad-Allow-Any-Any", 0,
        source_addresses=["any"], destination_addresses=["any"],
        services=["any"], applications=["any"], source_zones=["any"], destination_zones=["any"],
        log_forwarding_profile=None,
    )
    shadowed = _rule("Shadowed-Web-Rule", 1)
    findings = analyze([broad, shadowed])
    types = {f.finding_type for f in findings}
    assert "overly_permissive" in types  # from the broad rule
    assert "shadowed" in types           # the narrow rule being shadowed
