"""JSON reporter: full structured results with a stable, versioned schema."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from wraith import __version__
from wraith.engine import ScanResult
from wraith.models import Evidence, Finding, Severity

SCHEMA_VERSION = "1.0"


def finding_id(finding: Finding) -> str:
    """Stable across scans of the same target, so reports can be diffed."""
    key = "\x1f".join(finding.dedup_key).encode("utf-8")
    return hashlib.sha256(key).hexdigest()[:16]


def severity_counts(result: ScanResult) -> dict[str, int]:
    counts = {s.value: 0 for s in sorted(Severity, key=lambda s: -s.rank)}
    for f in result.findings:
        counts[f.severity.value] += 1
    return counts


def _evidence(ev: Evidence) -> dict[str, Any]:
    return {"request": ev.request, "response_snippet": ev.response_snippet, "matched": ev.matched}


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": finding_id(f),
        "check": f.check,
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "url": f.url,
        "description": f.description,
        "remediation": f.remediation,
        "references": list(f.references),
        "cvss": f.cvss,
        "evidence": [_evidence(ev) for ev in f.evidence],
    }


def to_dict(result: ScanResult, *, audit_log: str | None = None) -> dict[str, Any]:
    config, ctx = result.config, result.context
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "wraith", "version": __version__},
        "scan": {
            "target": config.target,
            "base_url": ctx.base_url,
            "scope": list(config.scope),
            "safe_mode": config.safe_mode,
            "started_at": result.started_at.isoformat(),
            "duration_s": round(result.duration_s, 3),
            "checks_run": list(result.checks_run),
            "requests_sent": result.requests_sent,
            "blocked_requests": result.blocked_requests,
            "audit_log": audit_log,
        },
        "summary": severity_counts(result),
        "findings": [finding_dict(f) for f in result.findings],
        "failures": [{"check": x.check, "error": x.error} for x in result.failures],
        "discovery": {
            "pages": [{"url": p.url, "status": p.status} for p in ctx.pages],
            "forms": [
                {
                    "page_url": form.page_url,
                    "action": form.action,
                    "method": form.method,
                    "parameters": list(form.parameters),
                }
                for form in ctx.forms
            ],
            "robots_paths": list(ctx.robots_paths),
            "sitemap_urls": list(ctx.sitemap_urls),
            "script_srcs": list(ctx.script_srcs),
            "tech_hints": [{"source": h.source, "value": h.value} for h in ctx.tech_hints],
            "off_scope_urls": list(ctx.off_scope_urls),
            "unsafe_urls_not_requested": list(ctx.unsafe_urls),
        },
    }


def render(result: ScanResult, *, audit_log: str | None = None) -> str:
    return json.dumps(to_dict(result, audit_log=audit_log), indent=2, ensure_ascii=False) + "\n"
