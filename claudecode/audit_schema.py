"""Schema helpers for normalized audit output."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from claudecode.security_policy import SecurityPolicy


AUDIT_SCHEMA_VERSION = "2.0"


def make_finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Create a stable fingerprint for finding deduplication."""
    canonical = {
        "file": finding.get("file") or finding.get("path") or "",
        "line": finding.get("line") or finding.get("start", {}).get("line") or 0,
        "severity": str(finding.get("severity", "")).upper(),
        "category": finding.get("category") or finding.get("check_id") or "",
        "description": finding.get("description")
        or finding.get("message")
        or finding.get("title")
        or "",
    }
    payload = json.dumps(canonical, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Copy finding and enrich with a stable fingerprint."""
    normalized = dict(finding)
    normalized.setdefault("fingerprint", make_finding_fingerprint(normalized))
    return normalized


def build_audit_output(
    repo_name: str,
    pr_number: int,
    findings: List[Dict[str, Any]],
    original_analysis_summary: Dict[str, Any],
    total_original_findings: int,
    excluded_findings: List[Dict[str, Any]],
    filter_analysis: Dict[str, Any],
    policy: SecurityPolicy,
    pipeline_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build final output while preserving backward-compatible fields."""
    normalized_findings = [normalize_finding(f) for f in findings]
    output: Dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "policy": {
            "name": policy.name,
            "version": policy.version,
            "source": policy.source,
            "min_confidence": policy.min_confidence,
        },
        "pr_number": pr_number,
        "repo": repo_name,
        "findings": normalized_findings,
        "analysis_summary": original_analysis_summary,
        "filtering_summary": {
            "total_original_findings": total_original_findings,
            "excluded_findings": len(excluded_findings),
            "kept_findings": len(normalized_findings),
            "filter_analysis": filter_analysis,
            "excluded_findings_details": excluded_findings,
        },
    }
    if pipeline_metadata:
        output["pipeline_metadata"] = pipeline_metadata
    return output
