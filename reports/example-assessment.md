# Zero Trust Access Assessment — Example

## Executive Summary

Three synthetic access requests were assessed. One request represents a well-governed workforce access path, while two demonstrate control failures requiring step-up or denial.

### ZT-001 — ALLOW

Managed compliant device, MFA present, low identity risk, segmented destination, encrypted HTTPS, approved protocol. No modeled policy gaps.

### ZT-002 — DENY

Key findings:
- **Critical:** high-sensitivity resource requested without MFA.
- **High:** identity risk exceeds the modeled threshold.
- **High:** device trust is unknown.
- **High:** device is non-compliant.

Recommended action: deny until identity assurance and endpoint posture are remediated, then replay the same normalized request for validation.

### ZT-003 — DENY

Key findings:
- **Critical:** unencrypted transport to a high-sensitivity resource.
- **High:** protocol is outside the explicit allowlist.
- **Medium:** sensitive resource shares the same source trust zone.

Recommended action: require protected transport, constrain the service to the approved protocol, and implement explicit segmentation before retest.

## ATT&CK Context

- T1078 — Valid Accounts
- T1021 — Remote Services
- T1040 — Network Sniffing
- T1557 — Adversary-in-the-Middle

These mappings explain defensive relevance only; no offensive techniques are executed by the project.
