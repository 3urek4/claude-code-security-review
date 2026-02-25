"""Unit tests for security_policy module."""

import json

import pytest

from claudecode.security_policy import (
    DEFAULT_POLICY_NAME,
    DEFAULT_POLICY_VERSION,
    PolicyValidationError,
    default_security_policy,
    load_security_policy,
)


def test_default_security_policy_with_overlays():
    policy = default_security_policy(
        custom_scan_instructions="Scan overlay",
        custom_filtering_instructions="Filter overlay",
    )

    assert policy.name == DEFAULT_POLICY_NAME
    assert policy.version == DEFAULT_POLICY_VERSION
    assert policy.source == "builtin"
    assert policy.scan_instructions == "Scan overlay"
    assert policy.filtering_instructions == "Filter overlay"


def test_load_security_policy_file_and_merge(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "version": "2026.1",
                "name": "team-policy",
                "scan_instructions": "base-scan",
                "filtering_instructions": "base-filter",
                "min_confidence": 0.9,
            }
        ),
        encoding="utf-8",
    )

    policy = load_security_policy(
        policy_file=str(policy_file),
        custom_scan_instructions="overlay-scan",
        custom_filtering_instructions="overlay-filter",
    )

    assert policy.version == "2026.1"
    assert policy.name == "team-policy"
    assert "base-scan" in policy.scan_instructions
    assert "overlay-scan" in policy.scan_instructions
    assert "base-filter" in policy.filtering_instructions
    assert "overlay-filter" in policy.filtering_instructions
    assert policy.min_confidence == 0.9
    assert str(policy_file) == policy.source


def test_load_security_policy_invalid_json(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text("{not-json", encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="Invalid policy JSON"):
        load_security_policy(policy_file=str(policy_file))
