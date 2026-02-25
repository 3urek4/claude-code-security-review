"""Application pipeline for orchestrating the full security audit flow."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from claudecode.audit_schema import build_audit_output
from claudecode.security_policy import SecurityPolicy


def apply_findings_filter_with_exclusions(
    findings_filter: Any,
    original_findings: List[Dict[str, Any]],
    pr_context: Dict[str, Any],
    is_excluded: Callable[[str], bool],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filtering and enforce final directory exclusions."""
    filter_success, filter_results, _filter_stats = findings_filter.filter_findings(
        original_findings, pr_context
    )

    if filter_success:
        kept_findings = filter_results.get("filtered_findings", [])
        excluded_findings = filter_results.get("excluded_findings", [])
        analysis_summary = filter_results.get("analysis_summary", {})
    else:
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}

    final_kept: List[Dict[str, Any]] = []
    excluded_by_directory: List[Dict[str, Any]] = []

    for finding in kept_findings:
        file_path = finding.get("file", "")
        if file_path and is_excluded(file_path):
            excluded_by_directory.append(finding)
        else:
            final_kept.append(finding)

    all_excluded = excluded_findings + excluded_by_directory
    analysis_summary["directory_excluded_count"] = len(excluded_by_directory)
    return final_kept, all_excluded, analysis_summary


@dataclass
class PipelineMetrics:
    """Timing and flow metrics for one pipeline execution."""

    started_at_unix: float = field(default_factory=time.time)
    stage_durations_ms: Dict[str, int] = field(default_factory=dict)
    prompt_used_diff: bool = True
    total_duration_ms: int = 0

    def mark_stage(self, stage_name: str, started_at: float) -> None:
        self.stage_durations_ms[stage_name] = int((time.time() - started_at) * 1000)

    def finalize(self) -> None:
        self.total_duration_ms = int((time.time() - self.started_at_unix) * 1000)


@dataclass
class PipelineResult:
    """Result returned by SecurityAuditPipeline.run()."""

    success: bool
    output: Optional[Dict[str, Any]] = None
    error_message: str = ""
    high_severity_count: int = 0
    metrics: Optional[PipelineMetrics] = None


class SecurityAuditPipeline:
    """End-to-end pipeline for collecting, scanning, filtering, and packaging results."""

    def __init__(
        self,
        github_client: Any,
        claude_runner: Any,
        findings_filter: Any,
        prompt_builder: Callable[..., str],
        policy: SecurityPolicy,
        logger: Any,
    ):
        self.github_client = github_client
        self.claude_runner = claude_runner
        self.findings_filter = findings_filter
        self.prompt_builder = prompt_builder
        self.policy = policy
        self.logger = logger

    def run(self, repo_name: str, pr_number: int, repo_dir: Path) -> PipelineResult:
        metrics = PipelineMetrics()

        try:
            started = time.time()
            pr_data = self.github_client.get_pr_data(repo_name, pr_number)
            pr_diff = self.github_client.get_pr_diff(repo_name, pr_number)
            metrics.mark_stage("collect_pr_context", started)
        except Exception as exc:
            return PipelineResult(
                success=False,
                error_message=f"Failed to fetch PR data: {exc}",
                metrics=metrics,
            )

        started = time.time()
        prompt = self.prompt_builder(
            pr_data, pr_diff, custom_scan_instructions=self.policy.scan_instructions
        )
        metrics.mark_stage("build_prompt", started)

        started = time.time()
        success, error_msg, scan_results = self.claude_runner.run_security_audit(repo_dir, prompt)
        if not success and error_msg == "PROMPT_TOO_LONG":
            self.logger.info(
                "Prompt too long, retrying without diff. Original prompt length: %s characters",
                len(prompt),
            )
            metrics.prompt_used_diff = False
            prompt = self.prompt_builder(
                pr_data,
                pr_diff,
                include_diff=False,
                custom_scan_instructions=self.policy.scan_instructions,
            )
            self.logger.info("Retry prompt length: %s characters", len(prompt))
            success, error_msg, scan_results = self.claude_runner.run_security_audit(repo_dir, prompt)
        metrics.mark_stage("run_scan", started)

        if not success:
            return PipelineResult(
                success=False,
                error_message=f"Security audit failed: {error_msg}",
                metrics=metrics,
            )

        started = time.time()
        original_findings = scan_results.get("findings", [])
        pr_context = {
            "repo_name": repo_name,
            "pr_number": pr_number,
            "title": pr_data.get("title", ""),
            "description": pr_data.get("body", ""),
        }

        kept_findings, excluded_findings, filter_analysis = apply_findings_filter_with_exclusions(
            findings_filter=self.findings_filter,
            original_findings=original_findings,
            pr_context=pr_context,
            is_excluded=self.github_client._is_excluded,
        )
        metrics.mark_stage("filter_findings", started)

        started = time.time()
        metrics.finalize()
        output = build_audit_output(
            repo_name=repo_name,
            pr_number=pr_number,
            findings=kept_findings,
            original_analysis_summary=scan_results.get("analysis_summary", {}),
            total_original_findings=len(original_findings),
            excluded_findings=excluded_findings,
            filter_analysis=filter_analysis,
            policy=self.policy,
            pipeline_metadata={
                "stage_durations_ms": metrics.stage_durations_ms,
                "total_duration_ms": metrics.total_duration_ms,
                "prompt_used_diff": metrics.prompt_used_diff,
            },
        )
        metrics.mark_stage("package_output", started)

        high_severity_count = len(
            [f for f in kept_findings if str(f.get("severity", "")).upper() == "HIGH"]
        )
        return PipelineResult(
            success=True,
            output=output,
            high_severity_count=high_severity_count,
            metrics=metrics,
        )
