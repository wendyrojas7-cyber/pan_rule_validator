"""
cli.py
======

Orchestrates a full run: Collector -> Normalizer -> Analysis -> Report.
This is Phase 1 of the architecture (see the accompanying architecture
doc) -- no AI layer is wired in yet. Findings are written as JSON so a
future Phase 2 process can pick them up and generate the risk narrative.

Usage:
    python -m pan_rule_validator.cli --config config.yaml --device-group DG-Edge-Firewalls

Config file (YAML) fields:
    panorama_host: panorama.internal.example.com
    api_key: "<pulled from your secrets manager, not committed to source>"
    verify_ssl: true
    device_groups:
      - DG-Edge-Firewalls
      - DG-DataCenter
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List

import yaml

from .analysis import analyze
from .collector import PanoramaClient, PanoramaConfig
from .normalizer import build_address_index, build_service_index, parse_rulebase
from .report import to_console, to_json, to_markdown

logger = logging.getLogger("pan_rule_validator")


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def run_device_group(client: PanoramaClient, device_group: str) -> list:
    logger.info("Pulling objects and rulebase for device group %s", device_group)

    shared_addresses = client.get_shared_objects("address").findall(".//entry")
    shared_address_groups = client.get_shared_objects("address-group").findall(".//entry")
    dg_addresses = client.get_device_group_objects(device_group, "address").findall(".//entry")
    dg_address_groups = client.get_device_group_objects(device_group, "address-group").findall(".//entry")

    shared_services = client.get_shared_objects("service").findall(".//entry")
    shared_service_groups = client.get_shared_objects("service-group").findall(".//entry")
    dg_services = client.get_device_group_objects(device_group, "service").findall(".//entry")
    dg_service_groups = client.get_device_group_objects(device_group, "service-group").findall(".//entry")

    address_index = build_address_index(
        shared_addresses + dg_addresses,
        shared_address_groups + dg_address_groups,
    )
    service_index = build_service_index(
        shared_services + dg_services,
        shared_service_groups + dg_service_groups,
    )

    for w in address_index.warnings + service_index.warnings:
        logger.warning(w)

    pre = client.get_device_group_rulebase(device_group, "pre-rulebase")
    post = client.get_device_group_rulebase(device_group, "post-rulebase")

    rules = parse_rulebase(pre, device_group, address_index, service_index)
    # Post-rules evaluate after pre-rules; keep positions continuing on from pre-rules
    post_rules = parse_rulebase(post, device_group, address_index, service_index)
    offset = len(rules)
    for r in post_rules:
        r["position"] += offset
    rules.extend(post_rules)

    return analyze(rules)


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Panorama security rulebases.")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    parser.add_argument("--device-group", action="append", dest="device_groups",
                         help="Device group to validate (repeatable). Defaults to all in config.")
    parser.add_argument("--format", choices=["console", "markdown", "json"], default="console")
    parser.add_argument("--output", help="Write report to this file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                         format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    panorama_cfg = PanoramaConfig(
        host=cfg["panorama_host"],
        api_key=cfg.get("api_key"),
        username=cfg.get("username"),
        password=cfg.get("password"),
        verify_ssl=cfg.get("verify_ssl", True),
    )
    client = PanoramaClient(panorama_cfg)

    device_groups = args.device_groups or cfg.get("device_groups", [])
    if not device_groups:
        logger.error("No device groups specified (via --device-group or config.device_groups)")
        return 2

    all_findings = []
    for dg in device_groups:
        all_findings.extend(run_device_group(client, dg))

    if args.format == "json":
        output = to_json(all_findings)
    elif args.format == "markdown":
        output = to_markdown(all_findings)
    else:
        output = to_console(all_findings)

    if args.output:
        Path(args.output).write_text(output)
        logger.info("Wrote report to %s", args.output)
    else:
        print(output)

    high_count = sum(1 for f in all_findings if f.severity == "high")
    return 1 if high_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
