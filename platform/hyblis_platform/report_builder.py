"""Build a platform-ready report (the bounty platform's submission format) from a validated submission.

The operator reviews and files it under their own account; nothing here contacts
any platform. Output is Markdown with the PoC as a fenced code block, matching
what a bounty platform's submission form expects (title, severity, description, PoC).
"""
from __future__ import annotations

import json

from . import config, store

TEMPLATE = """# {title}

**Severity:** {severity}

## Summary
{summary}

## Vulnerability Detail
{detail}

## Impact
{impact}

## Affected code
- Program task: `{task_id}`
- Contract: `{contract}`
- Function: `{function}`

## Proof of Concept
Foundry test, run against a mainnet fork pinned at the task's fork block. It was
reproduced deterministically twice by the Hyblis runner.

```solidity
{poc}
```

## Measured impact (Hyblis runner)
{measured}

## Recommendation
{recommendation}
"""


def build(sid: str) -> str:
    sub = store.get(sid)
    if not sub:
        raise KeyError(sid)
    if sub["status"] not in (config.STATUS_VALIDATED, config.STATUS_FILED, config.STATUS_ACCEPTED):
        raise ValueError(f"submission {sid} is {sub['status']}, not validated")
    pkg = json.loads(sub["package_json"])
    measured = json.loads(sub["measured_json"]) if sub["measured_json"] else {}
    sev = (sub["severity_final"] or sub["severity_claim"]).capitalize()

    ev = measured.get("evidence", {})
    measured_md = "\n".join(f"- **{k}:** {v}" for k, v in ev.items()) or "- (see runner verdict)"
    impact_type = measured.get("impact_type", "see detail")

    return TEMPLATE.format(
        title=pkg["header"]["title"],
        severity=sev,
        summary=pkg["header"]["description"].split("\n")[0][:400],
        detail=pkg["header"]["description"],
        impact=f"Impact type: {impact_type}. Measured severity: {sev}.",
        task_id=sub["task_id"],
        contract=sub["contract"],
        function=measured.get("changed_function") or sub["function"],
        poc=pkg["poc"].strip(),
        measured=measured_md,
        recommendation="(optional — add a fix suggestion before filing if desired)",
    )
