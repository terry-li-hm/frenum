"""Built-in rule implementations for limen."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from limen._types import Decision, RuleConfig, RuleResult, RuleType, ToolCall

# Rule handler registry
RuleHandler = Callable[[RuleConfig, ToolCall], RuleResult]
_RULE_REGISTRY: dict[RuleType, RuleHandler] = {}


def rule_handler(rule_type: RuleType) -> Callable[[RuleHandler], RuleHandler]:
    """Register a function as the handler for a rule type."""

    def decorator(fn: RuleHandler) -> RuleHandler:
        _RULE_REGISTRY[rule_type] = fn
        return fn

    return decorator


def get_handler(rule_type: RuleType) -> RuleHandler:
    """Look up the handler for a rule type."""
    handler = _RULE_REGISTRY.get(rule_type)
    if handler is None:
        raise ValueError(f"No handler registered for rule type: {rule_type.value}")
    return handler


# Built-in PII patterns (stdlib re only)
PII_PATTERNS: dict[str, str] = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone_intl": r"\+\d{1,3}[\s-]?\d{4,14}",
    "hk_id": r"[A-Z]{1,2}\d{6}\([0-9A]\)",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
}


def _extract_string_values(obj: Any) -> list[str]:
    """Recursively extract all string values from a nested structure."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_extract_string_values(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            strings.extend(_extract_string_values(item))
    return strings


@rule_handler(RuleType.REGEX_BLOCK)
def eval_regex_block(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Block if any specified field matches any pattern."""
    fields = rule.params.get("fields", [])
    patterns = rule.params.get("patterns", [])

    for field_name in fields:
        value = tool_call.args.get(field_name)
        if value is None:
            continue
        value_str = str(value)
        for pattern in patterns:
            match = re.search(pattern, value_str)
            if match:
                return RuleResult(
                    rule_name=rule.name,
                    rule_type=rule.rule_type.value,
                    decision=Decision.BLOCK,
                    reason=f"Pattern matched in field '{field_name}': {match.group()[:50]}",
                    matched_value=match.group()[:50],
                )

    return RuleResult(
        rule_name=rule.name,
        rule_type=rule.rule_type.value,
        decision=Decision.ALLOW,
        reason="No blocked patterns found",
    )


@rule_handler(RuleType.REGEX_REQUIRE)
def eval_regex_require(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Block if a required field is missing or doesn't match the pattern."""
    fields = rule.params.get("fields", [])
    pattern = rule.params.get("pattern", "")

    for field_name in fields:
        value = tool_call.args.get(field_name)
        if value is None:
            return RuleResult(
                rule_name=rule.name,
                rule_type=rule.rule_type.value,
                decision=Decision.BLOCK,
                reason=f"Required field '{field_name}' is missing",
            )
        if not re.fullmatch(pattern, str(value)):
            return RuleResult(
                rule_name=rule.name,
                rule_type=rule.rule_type.value,
                decision=Decision.BLOCK,
                reason=f"Field '{field_name}' does not match required pattern",
                matched_value=str(value)[:50],
            )

    return RuleResult(
        rule_name=rule.name,
        rule_type=rule.rule_type.value,
        decision=Decision.ALLOW,
        reason="All required fields present and valid",
    )


@rule_handler(RuleType.PII_DETECT)
def eval_pii_detect(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Scan all string values in args for PII patterns."""
    detectors = rule.params.get("detectors", [])
    action = rule.params.get("action", "block")

    all_strings = _extract_string_values(tool_call.args)
    text = " ".join(all_strings)

    for detector_name in detectors:
        pattern = PII_PATTERNS.get(detector_name)
        if pattern is None:
            continue
        match = re.search(pattern, text)
        if match:
            decision = Decision.BLOCK if action == "block" else Decision.ALLOW
            return RuleResult(
                rule_name=rule.name,
                rule_type=rule.rule_type.value,
                decision=decision,
                reason=f"PII detected ({detector_name}): {match.group()[:10]}***",
                matched_value=f"{match.group()[:10]}***",
            )

    return RuleResult(
        rule_name=rule.name,
        rule_type=rule.rule_type.value,
        decision=Decision.ALLOW,
        reason="No PII detected",
    )


@rule_handler(RuleType.ENTITLEMENT)
def eval_entitlement(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Check user role against tool allowlist."""
    roles: dict[str, list[str]] = rule.params.get("roles", {})
    default = rule.params.get("default", "block")
    role_field = rule.params.get("role_field", "user_id")

    user_id = getattr(tool_call, role_field, "") or tool_call.metadata.get(role_field, "")

    # Find user's role
    user_role = tool_call.metadata.get("role", "")
    if not user_role:
        # Check if user_id matches a role name directly
        if user_id in roles:
            user_role = user_id

    if not user_role or user_role not in roles:
        decision = Decision.BLOCK if default == "block" else Decision.ALLOW
        return RuleResult(
            rule_name=rule.name,
            rule_type=rule.rule_type.value,
            decision=decision,
            reason=f"No role mapping for user '{user_id}' (default: {default})",
        )

    allowed_tools = roles[user_role]
    if "*" in allowed_tools or tool_call.name in allowed_tools:
        return RuleResult(
            rule_name=rule.name,
            rule_type=rule.rule_type.value,
            decision=Decision.ALLOW,
            reason=f"Role '{user_role}' is allowed to call '{tool_call.name}'",
        )

    return RuleResult(
        rule_name=rule.name,
        rule_type=rule.rule_type.value,
        decision=Decision.BLOCK,
        reason=f"Role '{user_role}' is not allowed to call '{tool_call.name}'",
    )
