# Zero Trust Network Lab

A recruiter-facing security-engineering portfolio project that models **identity-aware, device-aware and network-aware access decisions** using deterministic policy logic and synthetic data.

## Problem Statement

Traditional perimeter trust is insufficient for modern hybrid environments. Access decisions should consider identity assurance, device posture, resource sensitivity, segmentation, transport security and approved communication paths rather than trusting a request because it originates from an internal network.

This project demonstrates how those signals can be normalized, evaluated, scored, reported and revalidated after remediation without connecting to production systems.

## Architecture

```text
Synthetic access telemetry
        |
        v
Fail-closed JSON loader
        |
        v
Immutable request model
        |
        v
Zero Trust policy engine
  | identity assurance
  | device trust/compliance
  | segmentation
  | transport protection
  | protocol allowlist
        |
        v
Allow / Challenge / Deny
        |
        +--> deterministic findings
        +--> 0-100 trust score
        +--> remediation guidance
        +--> Markdown evidence report
```

## Project Structure

```text
.
├── .github/workflows/ci.yml
├── data/synthetic_access_requests.json
├── docs/
│   ├── architecture.md
│   └── methodology.md
├── reports/example-assessment.md
├── src/
│   ├── __init__.py
│   ├── cli.py
│   ├── loader.py
│   ├── models.py
│   ├── policy_engine.py
│   └── reporting.py
└── tests/test_policy_engine.py
```

## Security Controls Modeled

| Control plane | Example check | Failure response |
|---|---|---|
| Identity | MFA required for high/critical resources | Critical finding / deny |
| Identity risk | Elevated risk score | Step-up or deny |
| Device | Unknown/untrusted device | Restrict or challenge |
| Endpoint posture | Non-compliant device | Require remediation |
| Network | Sensitive resource lacks explicit segmentation | Architectural finding |
| Transport | Connection is unencrypted | Critical finding / deny |
| Protocol | Protocol not explicitly approved | High finding |

## Decision Model

The policy engine starts with a trust score of 100 and applies bounded severity weights for explainability. Numeric scoring never overrides critical controls: any critical finding forces a deny decision. Requests with non-critical gaps are challenged or denied based on cumulative context.

This design intentionally avoids the anti-pattern of treating a network zone, VPN connection or single authentication event as sufficient proof of trust.

## Usage

Requires Python 3.11+ and no third-party packages.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_access_requests.json --report reports/generated-assessment.md
```

The CLI performs only offline analysis of synthetic JSON input.

## Remediation and Validation Workflow

1. Capture the failing request context and deterministic finding ID.
2. Identify the authoritative control source: identity, endpoint, segmentation, transport or application policy.
3. Apply the least-disruptive remediation without weakening adjacent controls.
4. Replay equivalent normalized evidence.
5. Confirm the targeted finding disappears and the access decision improves.
6. Preserve before/after output as auditable evidence.

See `docs/methodology.md` for detailed examples.

## MITRE ATT&CK Context

The project maps defensive controls to attacker behaviors they are intended to constrain:

- **T1078 — Valid Accounts**: identity assurance and risk-aware access decisions.
- **T1021 — Remote Services**: explicit protocol authorization and segmentation.
- **T1040 — Network Sniffing**: protected transport requirements.
- **T1557 — Adversary-in-the-Middle**: authenticated encryption requirements.

These mappings provide defensive context only. The repository does not execute ATT&CK techniques, exploit systems, capture credentials or target live infrastructure.

## Example Scenario

`data/synthetic_access_requests.json` contains three fictional requests:

- a compliant workforce request that should be allowed;
- a high-risk contractor request lacking MFA and endpoint compliance;
- a service-to-service request using unencrypted, unapproved transport with weak segmentation.

The dataset contains no employer, client or production information.

## Testing

`tests/test_policy_engine.py` contains 10 unit tests covering:

- allow decisions for compliant access;
- mandatory MFA;
- high identity risk;
- untrusted devices;
- transport encryption;
- protocol allowlisting;
- deterministic finding IDs;
- fail-closed validation;
- malformed input rejection;
- report generation and metrics.

## CI/CD Security Checks

GitHub Actions is configured with `contents: read` only. The workflow compiles the Python source, discovers and executes unit tests, and runs the synthetic assessment. No repository write token, secret, production endpoint or external scanner is required.

## Design Decisions

- **Deterministic over opaque:** decisions and finding IDs are reproducible.
- **Fail closed:** malformed security context is rejected instead of silently trusted.
- **Explicit controls over score-only security:** critical controls remain hard gates.
- **Synthetic by design:** portfolio evidence is realistic without exposing confidential data.
- **Offline first:** the project demonstrates engineering logic without accidental production targeting.

## Limitations

This is an educational portfolio implementation, not a replacement for a production ZTNA/NAC/IdP platform. It does not provide continuous authentication, certificate issuance, endpoint telemetry collection, policy distribution, traffic enforcement, behavioral analytics, high availability, privacy controls or break-glass operations. Real-world deployments also require exception governance, telemetry freshness guarantees and operational monitoring.

## Skills Demonstrated

- Zero Trust architecture and policy design
- Security engineering and deterministic control evaluation
- Identity and device-context reasoning
- Network segmentation and transport-security assessment
- Risk classification and remediation design
- Python data modeling and validation
- Security automation and CLI development
- Unit testing and defensive CI/CD
- MITRE ATT&CK contextual mapping
- Executive and technical security reporting

## Roadmap

- Add policy-as-code profiles for workforce, service and privileged access.
- Add time-bound exception governance with expiry validation.
- Add synthetic certificate and workload-identity signals.
- Add richer continuous-access evaluation events.
- Add machine-readable JSON/SARIF-style reporting.
- Add remediation SLA and control-coverage trend metrics.

## Safety and Ethics

This repository is intentionally defensive. It contains no exploit payloads, credential theft, bypass instructions, malware, persistence, C2 infrastructure or live targeting. All identities, devices, resources and access events are synthetic.
