"""Unit tests for audit_schema helpers."""

from claudecode.audit_schema import (
    AUDIT_SCHEMA_VERSION,
    build_audit_output,
    make_finding_fingerprint,
    normalize_finding,
)
from claudecode.security_policy import default_security_policy


def test_make_finding_fingerprint_is_stable():
    finding = {
        "file": "api/handler.py",
        "line": 42,
        "severity": "HIGH",
        "category": "sql_injection",
        "description": "Unsanitized input reaches query",
    }
    assert make_finding_fingerprint(finding) == make_finding_fingerprint(dict(finding))


def test_normalize_finding_adds_fingerprint():
    finding = {"file": "main.py", "line": 7, "severity": "LOW"}
    normalized = normalize_finding(finding)
    assert "fingerprint" in normalized
    assert normalized["file"] == "main.py"


def test_build_audit_output_keeps_legacy_fields():
    policy = default_security_policy()
    findings = [{"file": "a.py", "line": 1, "severity": "HIGH"}]

    output = build_audit_output(
        repo_name="owner/repo",
        pr_number=123,
        findings=findings,
        original_analysis_summary={"files_reviewed": 1},
        total_original_findings=1,
        excluded_findings=[],
        filter_analysis={"kept_findings": 1},
        policy=policy,
        pipeline_metadata={"total_duration_ms": 10},
    )

    assert output["schema_version"] == AUDIT_SCHEMA_VERSION
    assert output["pr_number"] == 123
    assert output["repo"] == "owner/repo"
    assert len(output["findings"]) == 1
    assert output["filtering_summary"]["kept_findings"] == 1
    assert "pipeline_metadata" in output
