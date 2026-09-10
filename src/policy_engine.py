import hashlib
from .models import AccessRequest, Decision, Finding

SEVERITY_WEIGHT = {"low": 5, "medium": 10, "high": 20, "critical": 30}


def _finding(req: AccessRequest, control: str, severity: str, reason: str, remediation: str, attack_ids=()):
    raw = f"{req.request_id}|{control}|{reason}".encode()
    fid = hashlib.sha256(raw).hexdigest()[:12]
    return Finding(fid, req.request_id, control, severity, reason, remediation, tuple(attack_ids))


def evaluate(req: AccessRequest) -> Decision:
    req.validate()
    findings = []

    if req.sensitivity in {"high", "critical"} and not req.mfa:
        findings.append(_finding(req, "identity.mfa", "critical", "Sensitive resource access lacks MFA", "Require phishing-resistant MFA before access.", ("T1078",)))
    if req.identity_risk >= 70:
        findings.append(_finding(req, "identity.risk", "high", f"Identity risk is {req.identity_risk}", "Step-up authentication or deny until identity risk is resolved.", ("T1078",)))
    if req.device_trust in {"unknown", "untrusted"}:
        findings.append(_finding(req, "device.trust", "high", f"Device trust is {req.device_trust}", "Require device enrollment or isolate through restricted access policy."))
    if not req.device_compliant:
        findings.append(_finding(req, "device.compliance", "high", "Device is non-compliant", "Remediate endpoint compliance before granting sensitive access."))
    if req.source_zone == req.destination_zone and req.sensitivity in {"high", "critical"}:
        findings.append(_finding(req, "network.segmentation", "medium", "Sensitive resource shares source trust zone", "Place sensitive resources behind explicit segmentation and identity-aware policy.", ("T1021",)))
    if not req.encrypted_channel:
        findings.append(_finding(req, "transport.encryption", "critical", "Connection is not encrypted", "Enforce authenticated TLS or equivalent protected transport.", ("T1040", "T1557")))
    if req.protocol not in req.approved_protocols:
        findings.append(_finding(req, "protocol.allowlist", "high", f"Protocol {req.protocol} is not approved", "Restrict access to documented approved protocols only.", ("T1021",)))

    score = max(0, 100 - sum(SEVERITY_WEIGHT[f.severity] for f in findings))
    action = "allow"
    if any(f.severity == "critical" for f in findings) or score < 60:
        action = "deny"
    elif findings:
        action = "challenge"
    return Decision(req.request_id, action, score, tuple(findings))
