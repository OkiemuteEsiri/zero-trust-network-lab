# Methodology and Remediation Validation

## Assessment method

The lab evaluates each synthetic access request against five control planes: identity assurance, device trust, network segmentation, transport protection, and protocol authorization. Resource sensitivity changes the required assurance level rather than assuming every access event has identical risk.

## Risk classification

- **Critical** — a control failure that should block access immediately, such as unencrypted transport or missing MFA for a critical resource.
- **High** — a strong risk indicator requiring denial or step-up depending on combined context, such as high identity risk or an untrusted/non-compliant device.
- **Medium** — architectural weakness requiring remediation, such as inadequate separation for sensitive resources.
- **Low** — hygiene or documentation issue with limited immediate security impact.

## Validation lifecycle

1. Capture the normalized failing request and finding ID.
2. Identify the authoritative control source: identity policy, device compliance policy, segmentation rule, transport configuration, or protocol allowlist.
3. Implement the least disruptive correction without weakening adjacent controls.
4. Replay equivalent normalized evidence.
5. Verify the targeted finding is absent and that the decision has improved.
6. Record before/after report output for auditability.

## Example remediation paths

| Finding | Primary remediation | Validation evidence |
|---|---|---|
| Missing MFA | Require phishing-resistant MFA for sensitive resources | MFA flag true; finding absent |
| High identity risk | Investigate account risk and require step-up authentication | Risk reduced or request denied until resolved |
| Unknown device | Enroll device or restrict access | Device trust becomes managed/trusted |
| Non-compliant endpoint | Correct posture failures | Compliance true |
| Weak segmentation | Move resource behind explicit policy boundary | Source and destination zones separated |
| Unencrypted transport | Require authenticated TLS/protected channel | encrypted_channel true |
| Unapproved protocol | Enforce explicit protocol allowlist | Requested protocol present in approved set |

## Constraints

This is a deterministic portfolio model. It does not claim to reproduce a commercial ZTNA platform, continuous risk engine, endpoint agent, NAC solution, or production identity provider. Real deployments require telemetry freshness, policy distribution, exception governance, break-glass design, availability engineering, privacy controls, and continuous monitoring.
