"""Unit tests for audit pipeline orchestration."""

from pathlib import Path
from unittest.mock import Mock

from claudecode.audit_pipeline import SecurityAuditPipeline
from claudecode.security_policy import default_security_policy


def _build_common_mocks():
    github_client = Mock()
    github_client.get_pr_data.return_value = {
        "title": "Test PR",
        "body": "Description",
    }
    github_client.get_pr_diff.return_value = "diff content"
    github_client._is_excluded.return_value = False

    findings_filter = Mock()
    findings_filter.filter_findings.return_value = (
        True,
        {
            "filtered_findings": [{"file": "a.py", "line": 10, "severity": "HIGH"}],
            "excluded_findings": [],
            "analysis_summary": {},
        },
        Mock(),
    )

    logger = Mock()
    prompt_builder = Mock(return_value="prompt")
    return github_client, findings_filter, logger, prompt_builder


def test_pipeline_success():
    github_client, findings_filter, logger, prompt_builder = _build_common_mocks()
    claude_runner = Mock()
    claude_runner.run_security_audit.return_value = (
        True,
        "",
        {"findings": [{"file": "a.py", "line": 10, "severity": "HIGH"}], "analysis_summary": {}},
    )

    pipeline = SecurityAuditPipeline(
        github_client=github_client,
        claude_runner=claude_runner,
        findings_filter=findings_filter,
        prompt_builder=prompt_builder,
        policy=default_security_policy(),
        logger=logger,
    )

    result = pipeline.run(repo_name="owner/repo", pr_number=123, repo_dir=Path("/tmp/repo"))
    assert result.success is True
    assert result.output is not None
    assert result.output["repo"] == "owner/repo"
    assert result.high_severity_count == 1


def test_pipeline_prompt_too_long_retries_without_diff():
    github_client, findings_filter, logger, prompt_builder = _build_common_mocks()
    prompt_builder.side_effect = ["prompt-with-diff", "prompt-without-diff"]

    claude_runner = Mock()
    claude_runner.run_security_audit.side_effect = [
        (False, "PROMPT_TOO_LONG", {}),
        (True, "", {"findings": [], "analysis_summary": {}}),
    ]

    pipeline = SecurityAuditPipeline(
        github_client=github_client,
        claude_runner=claude_runner,
        findings_filter=findings_filter,
        prompt_builder=prompt_builder,
        policy=default_security_policy(),
        logger=logger,
    )

    result = pipeline.run(repo_name="owner/repo", pr_number=123, repo_dir=Path("/tmp/repo"))
    assert result.success is True
    assert result.metrics is not None
    assert result.metrics.prompt_used_diff is False


def test_pipeline_collect_failure_returns_error():
    github_client = Mock()
    github_client.get_pr_data.side_effect = RuntimeError("GitHub API down")

    pipeline = SecurityAuditPipeline(
        github_client=github_client,
        claude_runner=Mock(),
        findings_filter=Mock(),
        prompt_builder=Mock(),
        policy=default_security_policy(),
        logger=Mock(),
    )

    result = pipeline.run(repo_name="owner/repo", pr_number=1, repo_dir=Path("/tmp/repo"))
    assert result.success is False
    assert "Failed to fetch PR data" in result.error_message
