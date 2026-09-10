from dataclasses import dataclass
from typing import FrozenSet

ALLOWED_TRUST = {"trusted", "managed", "unknown", "untrusted"}
ALLOWED_SENSITIVITY = {"low", "moderate", "high", "critical"}

@dataclass(frozen=True)
class AccessRequest:
    request_id: str
    subject: str
    device_id: str
    device_trust: str
    source_zone: str
    destination_zone: str
    resource: str
    sensitivity: str
    mfa: bool
    identity_risk: int
    device_compliant: bool
    encrypted_channel: bool
    approved_protocols: FrozenSet[str]
    protocol: str

    def validate(self) -> None:
        if not self.request_id or not self.subject or not self.resource:
            raise ValueError("request_id, subject and resource are required")
        if self.device_trust not in ALLOWED_TRUST:
            raise ValueError(f"invalid device_trust: {self.device_trust}")
        if self.sensitivity not in ALLOWED_SENSITIVITY:
            raise ValueError(f"invalid sensitivity: {self.sensitivity}")
        if not 0 <= self.identity_risk <= 100:
            raise ValueError("identity_risk must be 0..100")
        if not self.protocol:
            raise ValueError("protocol is required")

@dataclass(frozen=True)
class Finding:
    finding_id: str
    request_id: str
    control: str
    severity: str
    reason: str
    remediation: str
    attack_ids: tuple[str, ...] = ()

@dataclass(frozen=True)
class Decision:
    request_id: str
    action: str
    trust_score: int
    findings: tuple[Finding, ...]
