import json
from pathlib import Path
from .models import AccessRequest

REQUIRED = {
    "request_id", "subject", "device_id", "device_trust", "source_zone",
    "destination_zone", "resource", "sensitivity", "mfa", "identity_risk",
    "device_compliant", "encrypted_channel", "approved_protocols", "protocol"
}


def load_requests(path: str):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("top-level JSON must be a list")
    output = []
    for index, item in enumerate(data):
        missing = REQUIRED - set(item)
        if missing:
            raise ValueError(f"record {index} missing fields: {sorted(missing)}")
        req = AccessRequest(
            request_id=str(item["request_id"]), subject=str(item["subject"]), device_id=str(item["device_id"]),
            device_trust=str(item["device_trust"]), source_zone=str(item["source_zone"]),
            destination_zone=str(item["destination_zone"]), resource=str(item["resource"]),
            sensitivity=str(item["sensitivity"]), mfa=bool(item["mfa"]), identity_risk=int(item["identity_risk"]),
            device_compliant=bool(item["device_compliant"]), encrypted_channel=bool(item["encrypted_channel"]),
            approved_protocols=frozenset(map(str, item["approved_protocols"])), protocol=str(item["protocol"]),
        )
        req.validate()
        output.append(req)
    return output
