"""Built-in rule implementations for frenum."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from frenum._types import Decision, RuleConfig, RuleResult, ToolCall

# ---------------------------------------------------------------------------
# Rule handler registry
# ---------------------------------------------------------------------------

RuleHandler = Callable[[RuleConfig, ToolCall], RuleResult]
_RULE_REGISTRY: dict[str, RuleHandler] = {}


def rule_handler(rule_type: str) -> Callable[[RuleHandler], RuleHandler]:
    """Register a function as the handler for a rule type."""

    def decorator(fn: RuleHandler) -> RuleHandler:
        _RULE_REGISTRY[rule_type] = fn
        return fn

    return decorator


def get_handler(rule_type: str) -> RuleHandler:
    """Look up the handler for a rule type."""
    handler = _RULE_REGISTRY.get(rule_type)
    if handler is None:
        raise ValueError(
            f"Unknown rule type: {rule_type!r}. Valid: {sorted(_RULE_REGISTRY)}"
        )
    return handler


# ---------------------------------------------------------------------------
# Built-in PII patterns (stdlib re only)
# ---------------------------------------------------------------------------

PII_PATTERNS: dict[str, str] = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone_intl": r"\+\d{1,3}[\s-]?\d{4,14}",
    "hk_id": r"[A-Z]{1,2}\d{6}\([0-9A]\)",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
}


def _extract_strings(obj: Any) -> list[str]:
    """Recursively extract all string values from a nested structure."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_extract_strings(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            strings.extend(_extract_strings(item))
    return strings


# ---------------------------------------------------------------------------
# Rule handlers — 6 types
# ---------------------------------------------------------------------------


@rule_handler("regex_block")
def eval_regex_block(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Block if any specified field matches any pattern."""
    fields = rule.params.get("fields", [])
    patterns = rule.params.get("patterns", [])
    for field_name in fields:
        value = tool_call.args.get(field_name)
        if value is None:
            continue
        for pattern in patterns:
            match = re.search(pattern, str(value))
            if match:
                return RuleResult(
                    rule_name=rule.name,
                    rule_type=rule.rule_type,
                    decision=Decision.BLOCK,
                    reason=f"Pattern matched in '{field_name}': {match.group()[:50]}",
                    matched_value=match.group()[:50],
                )
    return RuleResult(
        rule_name=rule.name, rule_type=rule.rule_type,
        decision=Decision.ALLOW, reason="No blocked patterns found",
    )


@rule_handler("regex_require")
def eval_regex_require(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Block if a required field is missing or doesn't match pattern."""
    fields = rule.params.get("fields", [])
    pattern = rule.params.get("pattern", "")
    for field_name in fields:
        value = tool_call.args.get(field_name)
        if value is None:
            return RuleResult(
                rule_name=rule.name, rule_type=rule.rule_type,
                decision=Decision.BLOCK,
                reason=f"Required field '{field_name}' is missing",
            )
        if not re.fullmatch(pattern, str(value)):
            return RuleResult(
                rule_name=rule.name, rule_type=rule.rule_type,
                decision=Decision.BLOCK,
                reason=f"Field '{field_name}' does not match required pattern",
                matched_value=str(value)[:50],
            )
    return RuleResult(
        rule_name=rule.name, rule_type=rule.rule_type,
        decision=Decision.ALLOW, reason="All required fields valid",
    )


@rule_handler("pii_detect")
def eval_pii_detect(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Scan all string values in args for PII patterns."""
    detectors = rule.params.get("detectors", [])
    action = rule.params.get("action", "block")
    text = " ".join(_extract_strings(tool_call.args))
    for detector_name in detectors:
        pattern = PII_PATTERNS.get(detector_name)
        if pattern is None:
            continue
        match = re.search(pattern, text)
        if match:
            decision = Decision.BLOCK if action == "block" else Decision.ALLOW
            return RuleResult(
                rule_name=rule.name, rule_type=rule.rule_type,
                decision=decision,
                reason=f"PII detected ({detector_name})",
                matched_value=f"{match.group()[:10]}***",
            )
    return RuleResult(
        rule_name=rule.name, rule_type=rule.rule_type,
        decision=Decision.ALLOW, reason="No PII detected",
    )


@rule_handler("entitlement")
def eval_entitlement(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Check user role against tool allowlist."""
    roles: dict[str, list[str]] = rule.params.get("roles", {})
    default = rule.params.get("default", "block")
    user_role = tool_call.metadata.get("role", "")
    if not user_role or user_role not in roles:
        decision = Decision.BLOCK if default == "block" else Decision.ALLOW
        return RuleResult(
            rule_name=rule.name, rule_type=rule.rule_type,
            decision=decision,
            reason=f"No role mapping for role '{user_role}' (default: {default})",
        )
    allowed = roles[user_role]
    if "*" in allowed or tool_call.name in allowed:
        return RuleResult(
            rule_name=rule.name, rule_type=rule.rule_type,
            decision=Decision.ALLOW,
            reason=f"Role '{user_role}' allowed to call '{tool_call.name}'",
        )
    return RuleResult(
        rule_name=rule.name, rule_type=rule.rule_type,
        decision=Decision.BLOCK,
        reason=f"Role '{user_role}' not allowed to call '{tool_call.name}'",
    )


@rule_handler("budget")
def eval_budget(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Block if estimated_cost in metadata exceeds threshold."""
    max_cost = rule.params.get("max_cost", 0)
    cost_field = rule.params.get("cost_field", "estimated_cost")
    cost = tool_call.metadata.get(cost_field)
    if cost is None:
        on_missing = rule.params.get("on_missing", "allow")
        decision = Decision.BLOCK if on_missing == "block" else Decision.ALLOW
        return RuleResult(
            rule_name=rule.name, rule_type=rule.rule_type,
            decision=decision, reason=f"No {cost_field} in metadata",
        )
    try:
        cost_val = float(cost)
    except (TypeError, ValueError):
        return RuleResult(
            rule_name=rule.name, rule_type=rule.rule_type,
            decision=Decision.BLOCK,
            reason=f"Invalid {cost_field}: {cost!r}",
        )
    if cost_val > max_cost:
        return RuleResult(
            rule_name=rule.name, rule_type=rule.rule_type,
            decision=Decision.BLOCK,
            reason=f"Cost {cost_val} exceeds threshold {max_cost}",
        )
    return RuleResult(
        rule_name=rule.name, rule_type=rule.rule_type,
        decision=Decision.ALLOW,
        reason=f"Cost {cost_val} within threshold {max_cost}",
    )


@rule_handler("tool_allowlist")
def eval_tool_allowlist(rule: RuleConfig, tool_call: ToolCall) -> RuleResult:
    """Block if tool name is not in the allowed list."""
    allowed_tools: list[str] = rule.params.get("allowed_tools", [])
    if tool_call.name in allowed_tools:
        return RuleResult(
            rule_name=rule.name, rule_type=rule.rule_type,
            decision=Decision.ALLOW,
            reason=f"Tool '{tool_call.name}' is in allowlist",
        )
    return RuleResult(
        rule_name=rule.name, rule_type=rule.rule_type,
        decision=Decision.BLOCK,
        reason=f"Tool '{tool_call.name}' not in allowlist",
    )
