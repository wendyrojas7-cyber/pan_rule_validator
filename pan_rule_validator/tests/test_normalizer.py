import xml.etree.ElementTree as ET

import pytest

from pan_rule_validator.normalizer import (
    ResolutionError,
    build_address_index,
    build_service_index,
    parse_rulebase,
)


def _el(xml_str: str) -> ET.Element:
    return ET.fromstring(xml_str)


def test_address_leaf_resolution():
    addr = _el('<entry name="Web1"><ip-netmask>10.0.0.5/32</ip-netmask></entry>')
    index = build_address_index([addr], [])
    assert index.resolved["Web1"] == ["10.0.0.5/32"]
    assert index.warnings == []


def test_address_group_recursive_resolution():
    a1 = _el('<entry name="A1"><ip-netmask>10.0.0.1/32</ip-netmask></entry>')
    a2 = _el('<entry name="A2"><ip-netmask>10.0.0.2/32</ip-netmask></entry>')
    inner_group = _el('<entry name="InnerGrp"><static><member>A2</member></static></entry>')
    outer_group = _el(
        '<entry name="OuterGrp"><static><member>A1</member><member>InnerGrp</member></static></entry>'
    )
    index = build_address_index([a1, a2], [inner_group, outer_group])
    assert set(index.resolved["OuterGrp"]) == {"10.0.0.1/32", "10.0.0.2/32"}


def test_address_group_cycle_detection():
    grp_a = _el('<entry name="GrpA"><static><member>GrpB</member></static></entry>')
    grp_b = _el('<entry name="GrpB"><static><member>GrpA</member></static></entry>')
    with pytest.raises(ResolutionError):
        build_address_index([], [grp_a, grp_b])


def test_unresolved_address_reference_is_warned_not_raised():
    grp = _el('<entry name="GrpWithGhost"><static><member>DoesNotExist</member></static></entry>')
    index = build_address_index([], [grp])
    assert index.resolved["GrpWithGhost"] == ["unresolved:DoesNotExist"]
    assert any("DoesNotExist" in w for w in index.warnings)


def test_dynamic_address_group_marked_unresolved():
    dyn = _el('<entry name="DynGrp"><dynamic><filter>\'tag1\'</filter></dynamic></entry>')
    index = build_address_index([], [dyn])
    assert index.resolved["DynGrp"][0].startswith("dynamic-unresolved:")


def test_service_leaf_and_group_resolution():
    svc1 = _el(
        '<entry name="Svc443"><protocol><tcp><port>443</port></tcp></protocol></entry>'
    )
    svc2 = _el(
        '<entry name="Svc8443"><protocol><tcp><port>8443</port></tcp></protocol></entry>'
    )
    grp = _el(
        '<entry name="WebSvcs"><members><member>Svc443</member><member>Svc8443</member></members></entry>'
    )
    index = build_service_index([svc1, svc2], [grp])
    assert index.resolved["Svc443"] == ["tcp/443"]
    assert set(index.resolved["WebSvcs"]) == {"tcp/443", "tcp/8443"}


def test_parse_rulebase_resolves_rule_addresses_and_services():
    addr = _el('<entry name="Web1"><ip-netmask>10.0.0.5/32</ip-netmask></entry>')
    address_index = build_address_index([addr], [])
    svc = _el('<entry name="Svc443"><protocol><tcp><port>443</port></tcp></protocol></entry>')
    service_index = build_service_index([svc], [])

    rulebase = _el(
        """
        <rules>
          <entry name="Allow-Web">
            <from><member>untrust</member></from>
            <to><member>dmz</member></to>
            <source><member>any</member></source>
            <destination><member>Web1</member></destination>
            <service><member>Svc443</member></service>
            <application><member>ssl</member></application>
            <action>allow</action>
          </entry>
        </rules>
        """
    )
    rules = parse_rulebase(rulebase, "DG-Test", address_index, service_index)
    assert len(rules) == 1
    r = rules[0]
    assert r["rule_name"] == "Allow-Web"
    assert r["source_addresses"] == ["any"]
    assert r["destination_addresses"] == ["10.0.0.5/32"]
    assert r["services"] == ["tcp/443"]
    assert r["disabled"] is False
