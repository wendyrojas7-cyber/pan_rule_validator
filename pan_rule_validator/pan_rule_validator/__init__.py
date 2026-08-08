"""
pan_rule_validator
===================

An in-house pipeline for validating Palo Alto Networks security rulebases
managed through Panorama. See README.md for architecture and usage.

Modules:
    collector   - pulls rulebase + object config from Panorama's XML API
    normalizer  - resolves address/service/application objects into flat,
                  self-contained rule records
    analysis    - deterministic shadowing / redundancy / hygiene checks
    report      - renders findings as console / markdown / JSON output
    cli         - orchestrates a full run
"""

__version__ = "0.1.0"
