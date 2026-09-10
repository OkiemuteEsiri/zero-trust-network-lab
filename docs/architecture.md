# Architecture

## Objective

This lab models a defensive zero-trust access decision pipeline. It does not connect to production identity providers, endpoints, firewalls, or cloud services. Inputs are synthetic normalized access requests.

## Flow

1. **Ingestion** — `src.loader` validates required fields and converts JSON into immutable `AccessRequest` objects.
2. **Policy evaluation** — `src.policy_engine` evaluates identity, device, segmentation, transport, and protocol controls.
3. **Decisioning** — requests are classified as `allow`, `challenge`, or `deny` using explicit findings plus a bounded trust score.
4. **Reporting** — `src.reporting` produces portfolio metrics and human-readable remediation guidance.
5. **Validation** — the same normalized request is replayed after control changes to prove the finding has been resolved.

## Security design principles

- Default-deny for critical control failure.
- Never infer trust from network location alone.
- Identity, device posture, transport security, resource sensitivity, and protocol authorization are independent inputs.
- Findings use deterministic identifiers to support before/after remediation evidence.
- Malformed or incomplete data fails closed.
- The engine is deterministic and offline; there is no external targeting or active network enforcement.

## Components

- `models.py`: immutable domain objects and validation.
- `loader.py`: fail-closed ingestion.
- `policy_engine.py`: control evaluation and trust decisions.
- `reporting.py`: metrics and Markdown output.
- `cli.py`: local execution entry point.

## Trust score

The score starts at 100 and subtracts bounded weights for policy findings. It is an explainability aid, not a replacement for explicit policy gates. Any critical finding causes a denial even if the remaining numeric score would otherwise be acceptable.

## ATT&CK context

Relevant defensive mappings include T1078 Valid Accounts, T1021 Remote Services, T1040 Network Sniffing, and T1557 Adversary-in-the-Middle. Mappings describe the attacker behaviors that the modeled controls help constrain; this repository does not implement those offensive techniques.
