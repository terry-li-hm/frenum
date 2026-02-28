"""Static analysis for frenum policy configurations."""

from __future__ import annotations

import re

from frenum._types import LintWarning, RuleConfig
from frenum.rules import _RULE_REGISTRY, PII_PATTERNS


def lint_policy(rules: list[RuleConfig]) -> list[LintWarning]:
    """Check a list of policy rules for common errors and warnings.

    Error codes:
        E001 — Invalid regex pattern
        E002 — Unknown PII detector
        E003 — Duplicate rule name

    Warning codes:
        W001 — Empty applies_to (rule will never match)
        W002 — Missing required parameter for rule type
        W003 — Unknown rule type
    """
    warnings: list[LintWarning] = []
    seen_names: set[str] = set()

    required_params: dict[str, list[str]] = {
        "regex_block": ["fields", "patterns"],
        "regex_require": ["fields", "pattern"],
        "pii_detect": ["detectors"],
        "entitlement": ["roles"],
        "budget": ["max_cost"],
        "tool_allowlist": ["allowed_tools"],
    }

    for rule in rules:
        # E003: Duplicate rule names
        if rule.name in seen_names:
            warnings.append(
                LintWarning(
                    rule_name=rule.name,
                    code="E003",
                    message=f"Duplicate rule name: '{rule.name}'",
                    severity="error",
                )
            )
        seen_names.add(rule.name)

        # W003: Unknown rule type (single-sourced from registry)
        if rule.rule_type not in _RULE_REGISTRY:
            warnings.append(
                LintWarning(
                    rule_name=rule.name,
                    code="W003",
                    message=f"Unknown rule type: '{rule.rule_type}'",
                    severity="warning",
                )
            )

        # W001: Empty applies_to list
        if not rule.applies_to:
            warnings.append(
                LintWarning(
                    rule_name=rule.name,
                    code="W001",
                    message="Rule 'applies_to' list is empty; "
                    "this rule will never match.",
                    severity="warning",
                )
            )

        # W002: Missing required params
        if rule.rule_type in required_params:
            for param in required_params[rule.rule_type]:
                if param not in rule.params:
                    warnings.append(
                        LintWarning(
                            rule_name=rule.name,
                            code="W002",
                            message=(
                                f"Missing required parameter '{param}' "
                                f"for rule type '{rule.rule_type}'"
                            ),
                            severity="warning",
                        )
                    )

        # E001: Invalid regex pattern
        if rule.rule_type == "regex_block":
            patterns = rule.params.get("patterns", [])
            if isinstance(patterns, list):
                for p in patterns:
                    try:
                        re.compile(str(p))
                    except re.error as e:
                        warnings.append(
                            LintWarning(
                                rule_name=rule.name,
                                code="E001",
                                message=f"Invalid regex pattern '{p}': {e}",
                                severity="error",
                            )
                        )
        elif rule.rule_type == "regex_require":
            pattern = rule.params.get("pattern")
            if pattern:
                try:
                    re.compile(str(pattern))
                except re.error as e:
                    warnings.append(
                        LintWarning(
                            rule_name=rule.name,
                            code="E001",
                            message=f"Invalid regex pattern '{pattern}': {e}",
                            severity="error",
                        )
                    )

        # E002: Unknown PII detector (single-sourced from PII_PATTERNS)
        if rule.rule_type == "pii_detect":
            detectors = rule.params.get("detectors", [])
            if isinstance(detectors, list):
                for d in detectors:
                    if d not in PII_PATTERNS:
                        warnings.append(
                            LintWarning(
                                rule_name=rule.name,
                                code="E002",
                                message=f"Unknown PII detector: '{d}'",
                                severity="error",
                            )
                        )

    return warnings
