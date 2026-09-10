from collections import Counter
from .models import Decision


def metrics(decisions: list[Decision]) -> dict:
    actions = Counter(d.action for d in decisions)
    findings = [f for d in decisions for f in d.findings]
    severities = Counter(f.severity for f in findings)
    avg = round(sum(d.trust_score for d in decisions) / len(decisions), 1) if decisions else 0.0
    return {"requests": len(decisions), "actions": dict(actions), "findings": len(findings), "severities": dict(severities), "average_trust_score": avg}


def markdown(decisions: list[Decision]) -> str:
    m = metrics(decisions)
    lines = ["# Zero Trust Access Assessment", "", "## Executive Summary", "", f"- Requests assessed: **{m['requests']}**", f"- Findings: **{m['findings']}**", f"- Average trust score: **{m['average_trust_score']}**", f"- Decisions: `{m['actions']}`", "", "## Decision Detail", ""]
    for d in decisions:
        lines += [f"### {d.request_id}: {d.action.upper()} ({d.trust_score}/100)", ""]
        if not d.findings:
            lines += ["No policy gaps identified in the supplied synthetic context.", ""]
            continue
        for f in d.findings:
            attack = f" ATT&CK: {', '.join(f.attack_ids)}." if f.attack_ids else ""
            lines += [f"- **{f.severity.upper()} — {f.control}**: {f.reason}. {f.remediation}{attack}"]
        lines.append("")
    lines += ["## Validation Workflow", "", "1. Correct the authoritative identity, device, network, or application policy source.", "2. Re-run the same normalized request context through the engine.", "3. Confirm the finding disappears and the decision improves without weakening another control.", "4. Preserve before/after evidence for auditability."]
    return "\n".join(lines) + "\n"
