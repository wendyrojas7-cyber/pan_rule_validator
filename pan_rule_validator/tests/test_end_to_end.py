"""
Exercises Collector -> Normalizer -> Analysis together, with the Panorama
XML API mocked out. This is the synthetic-rulebase test the architecture
doc recommends building before trusting the pipeline against a real
Panorama instance.
"""

import xml.etree.ElementTree as ET

from pan_rule_validator.cli import run_device_group


class FakePanoramaClient:
    """Stands in for collector.PanoramaClient. Returns canned XML for a
    small synthetic rulebase with a known shadowing case and a known
    overly-permissive rule, so we can assert on exact expected findings.
    """

    def get_shared_objects(self, kind):
        return ET.fromstring("<result/>")  # nothing shared in this fixture

    def get_device_group_objects(self, device_group, kind):
        if kind == "address":
            return ET.fromstring(
                '<result><entry name="Web1"><ip-netmask>10.0.0.5/32</ip-netmask></entry></result>'
            )
        if kind == "service":
            return ET.fromstring(
                '<result><entry name="Svc443"><protocol><tcp><port>443</port></tcp></protocol></entry></result>'
            )
        return ET.fromstring("<result/>")

    def get_device_group_rulebase(self, device_group, pre_or_post):
        if pre_or_post == "pre-rulebase":
            return ET.fromstring(
                """
                <result>
                <rules>
                  <entry name="Broad-Allow-Any-Any">
                    <from><member>any</member></from>
                    <to><member>any</member></to>
                    <source><member>any</member></source>
                    <destination><member>any</member></destination>
                    <service><member>any</member></service>
                    <application><member>any</member></application>
                    <action>allow</action>
                  </entry>
                  <entry name="Narrow-Allow-Web">
                    <from><member>untrust</member></from>
                    <to><member>dmz</member></to>
                    <source><member>any</member></source>
                    <destination><member>Web1</member></destination>
                    <service><member>Svc443</member></service>
                    <application><member>ssl</member></application>
                    <action>allow</action>
                    <log-setting>default-forward</log-setting>
                  </entry>
                </rules>
                </result>
                """
            )
        return ET.fromstring("<result><rules/></result>")  # empty post-rulebase


def test_end_to_end_flags_shadowing_and_overly_permissive():
    client = FakePanoramaClient()
    findings = run_device_group(client, "DG-Test")

    by_type = {}
    for f in findings:
        by_type.setdefault(f.finding_type, []).append(f)

    assert "shadowed" in by_type
    shadowed_names = {f.rule_name for f in by_type["shadowed"]}
    assert "Narrow-Allow-Web" in shadowed_names

    assert "overly_permissive" in by_type
    permissive_names = {f.rule_name for f in by_type["overly_permissive"]}
    assert "Broad-Allow-Any-Any" in permissive_names
