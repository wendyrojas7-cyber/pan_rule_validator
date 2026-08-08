# pan_rule_validator

**Focus:** Python automation tool for validating Palo Alto Panorama firewall rulebases, combining a deterministic rule-analysis engine with an AI-generated narrative layer.

**Python / Panorama / Firewall Rule Auditing / AI-Assisted Reporting**

---

## What it does

`pan_rule_validator` audits a Panorama firewall rulebase and flags issues a manual review would otherwise catch slowly or inconsistently — things like overly permissive rules, shadowed/unreachable rules, unused objects, and rules that drift from least-privilege intent. The tool is built in two layers:

1. **Deterministic analysis engine** — parses the rulebase and applies a fixed set of rule-hygiene checks (permissiveness, shadowing, redundancy, missing logging, stale objects). This layer is fully repeatable: same input, same findings, every time.
2. **AI narrative layer** — takes the deterministic engine's structured findings and generates a plain-language summary and risk narrative (via the Claude API), so the output is readable by people who didn't write the rulebase, not just a list of rule IDs and flags.

Separating these two layers deliberately: the analysis itself never depends on an LLM's judgment call, only on fixed logic — the AI layer's job is strictly to explain findings that already exist, not to decide what counts as a finding.

## Status

Reached Phase 2 of development with 33 passing tests covering the deterministic analysis engine.

## Why this project

Manual rulebase reviews are slow, inconsistent between reviewers, and easy to defer under operational load — which is exactly how rule sprawl and permissive shortcuts accumulate over time. This was built to make that review fast enough to run regularly instead of only during audits, while keeping the actual security judgment (what counts as a violation) deterministic and auditable rather than left to an LLM.

## Tech

- **Language:** Python
- **Testing:** pytest, 33 passing tests (Phase 2)
- **AI integration:** Anthropic Claude API for narrative generation
- **Target platform:** Palo Alto Panorama

---

*Note on content: This is a personal project built to explore rule-validation automation and AI-assisted security reporting. No production rulebase data, hostnames, or organization-specific configuration is included in this repository.*
