"""SARIF 2.1.0 reporter for CI pipelines and code-scanning dashboards."""

from __future__ import annotations

import json
import re
from typing import Any

from wraith import __version__
from wraith.engine import ScanResult
from wraith.models import Finding, Severity
from wraith.reporting.json_report import finding_id

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {  # GitHub code scanning maps this to its own severity scale
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def rule_id(finding: Finding) -> str:
    # Strip quoted cookie names etc. so one rule covers every instance.
    title = re.sub(r"'[^']*'", "", finding.title.lower())
    slug = re.sub(r"[^a-z0-9]+", "-", title).strip("-")
    return f"{finding.check}/{slug}"


def to_dict(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in result.findings:
        rid = rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "help": {"text": f.remediation},
                "helpUri": f.references[0] if f.references else None,
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "tags": ["security", f.check],
                },
            }
        results.append(
            {
                "ruleId": rid,
                "level": _LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
                "partialFingerprints": {"wraithFindingId": finding_id(f)},
                "properties": {
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "remediation": f.remediation,
                },
            }
        )
    for rule in rules.values():
        if rule["helpUri"] is None:
            del rule["helpUri"]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WRAITH",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not result.failures,
                        "startTimeUtc": result.started_at.isoformat().replace("+00:00", "Z"),
                    }
                ],
                "results": results,
            }
        ],
    }


def render(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"
