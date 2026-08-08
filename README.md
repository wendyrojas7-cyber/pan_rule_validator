# pan_rule_validator

Phase 1 implementation of the AI-assisted Panorama rule validation pipeline

This phase is fully deterministic \u2014 no LLM calls yet. It pulls a security
rulebase from Panorama, resolves every address/service object reference,
and flags:

- **Shadowed rules** \u2014 an earlier rule already matches everything a later
  rule would match, so the later rule is unreachable.
- **Redundant rules** \u2014 identical match criteria and action to an earlier
  rule.
- **Overly permissive rules** \u2014 `any`/`any` allows, wide-open services,
  non-App-ID-scoped applications, or missing log-forwarding profiles.
- **Hygiene issues** \u2014 disabled rules, references to deleted objects,
  and dynamic (tag-based) address groups that can't be resolved statically.

The AI risk-narrative layer described in the architecture doc is Phase 2:
it will take this module's JSON findings output as input and is
intentionally not part of this codebase yet, so the deterministic logic
can be trusted and tested on its own first.

## Project layout

```
pan_rule_validator/
  __init__.py
  collector.py    Panorama XML API client (read-only: keygen + config get)
  normalizer.py   Resolves address/service objects, flattens rules to JSON
  analysis.py     Deterministic shadowing/redundancy/permissiveness/hygiene checks
  report.py       Console / Markdown / JSON output
  cli.py          Orchestrates a full run
tests/
  test_normalizer.py    Object resolution incl. recursive groups + cycle detection
  test_analysis.py      Every check, incl. CIDR/port-range superset edge cases
  test_end_to_end.py    Full pipeline against a mocked Panorama client
config.example.yaml
requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
# edit config.yaml: panorama_host, api_key (from your secrets manager), device_groups
```

**Do not commit `config.yaml` with a real API key or password.** The
`api_key` field should be populated at deploy time from Key Vault (or
equivalent), not stored in the repo.

## Running

```bash
python -m pan_rule_validator.cli --config config.yaml --format markdown --output findings.md
```

```bash
# Validate a specific device group only, print to console
python -m pan_rule_validator.cli --config config.yaml --device-group DG-Edge-Firewalls
```

Exit code is `1` if any high-severity finding was produced (useful for a
pre-commit gate / CI check), `0` otherwise.

## Running the tests

```bash
pytest -v
```

All object-resolution and rule-analysis logic is covered by synthetic
fixtures \u2014 no live Panorama connection is required to run the test suite.
This is deliberate: the deterministic engine should be proven against known-answer synthetic
rulebases before anything else (scheduling, the AI layer, ticketing) gets
layered on top.

## Known limitations (by design, for this phase)

- **Read-only.** No commit/write operations are ever called against Panorama.
- **Security rulebase only** \u2014 NAT and QoS policies are out of scope.
- **Dynamic (tag-based) address groups** can't be resolved from static
  config alone; they're flagged for manual review rather than silently
  mis-evaluated.
- **Hit-count / usage data** (for "zero-hit rule" cleanup candidates) isn't
  wired in yet \u2014 depends on which Policy Optimizer data your PAN-OS version
  exposes via the API.
- **Exact XML schema details** (tag names, nesting) should be verified
  against your specific PAN-OS version before pointing this at production
  Panorama \u2014.
