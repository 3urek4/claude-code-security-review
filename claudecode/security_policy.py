"""Policy loading and validation for security audit behavior."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_POLICY_VERSION = "1.0"
DEFAULT_POLICY_NAME = "default-security-review-policy"


class PolicyValidationError(ValueError):
    """Raised when a policy file is invalid."""


@dataclass(frozen=True)
class SecurityPolicy:
    """Versioned policy bundle used by the security audit pipeline."""

    version: str
    name: str
    source: str
    scan_instructions: str = ""
    filtering_instructions: str = ""
    min_confidence: float = 0.8


def _merge_instructions(base: str, extra: Optional[str]) -> str:
    if not extra:
        return base
    if not base:
        return extra
    return f"{base.rstrip()}\n\n{extra.lstrip()}"


def _validate_policy_dict(data: Dict[str, Any], source: str) -> SecurityPolicy:
    if not isinstance(data, dict):
        raise PolicyValidationError(f"Policy must be a JSON object: {source}")

    version = data.get("version", DEFAULT_POLICY_VERSION)
    name = data.get("name", DEFAULT_POLICY_NAME)
    scan_instructions = data.get("scan_instructions", "")
    filtering_instructions = data.get("filtering_instructions", "")
    min_confidence = data.get("min_confidence", 0.8)

    if not isinstance(version, str) or not version.strip():
        raise PolicyValidationError(f"Policy version must be a non-empty string: {source}")
    if not isinstance(name, str) or not name.strip():
        raise PolicyValidationError(f"Policy name must be a non-empty string: {source}")
    if not isinstance(scan_instructions, str):
        raise PolicyValidationError(f"scan_instructions must be a string: {source}")
    if not isinstance(filtering_instructions, str):
        raise PolicyValidationError(f"filtering_instructions must be a string: {source}")
    if not isinstance(min_confidence, (int, float)):
        raise PolicyValidationError(f"min_confidence must be numeric: {source}")
    if min_confidence < 0.0 or min_confidence > 1.0:
        raise PolicyValidationError(f"min_confidence must be between 0 and 1: {source}")

    return SecurityPolicy(
        version=version.strip(),
        name=name.strip(),
        source=source,
        scan_instructions=scan_instructions.strip(),
        filtering_instructions=filtering_instructions.strip(),
        min_confidence=float(min_confidence),
    )


def default_security_policy(
    custom_scan_instructions: Optional[str] = None,
    custom_filtering_instructions: Optional[str] = None,
) -> SecurityPolicy:
    """Return default policy with optional custom instruction overlays."""
    return SecurityPolicy(
        version=DEFAULT_POLICY_VERSION,
        name=DEFAULT_POLICY_NAME,
        source="builtin",
        scan_instructions=(custom_scan_instructions or "").strip(),
        filtering_instructions=(custom_filtering_instructions or "").strip(),
    )


def load_security_policy(
    policy_file: Optional[str] = None,
    custom_scan_instructions: Optional[str] = None,
    custom_filtering_instructions: Optional[str] = None,
) -> SecurityPolicy:
    """Load policy from file (if provided) and merge custom instruction overlays."""
    if not policy_file:
        return default_security_policy(custom_scan_instructions, custom_filtering_instructions)

    path = Path(policy_file)
    if not path.exists():
        raise PolicyValidationError(f"Policy file does not exist: {policy_file}")
    if not path.is_file():
        raise PolicyValidationError(f"Policy path is not a file: {policy_file}")

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyValidationError(f"Invalid policy JSON in {policy_file}: {exc}") from exc
    except OSError as exc:
        raise PolicyValidationError(f"Failed to read policy file {policy_file}: {exc}") from exc

    policy = _validate_policy_dict(data, source=str(path))
    return SecurityPolicy(
        version=policy.version,
        name=policy.name,
        source=policy.source,
        scan_instructions=_merge_instructions(policy.scan_instructions, custom_scan_instructions).strip(),
        filtering_instructions=_merge_instructions(
            policy.filtering_instructions, custom_filtering_instructions
        ).strip(),
        min_confidence=policy.min_confidence,
    )
