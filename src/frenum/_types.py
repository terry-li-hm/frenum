"""Core types for frenum — deterministic guardrails for LLM agent tool calls."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"


class RuleType(Enum):
    REGEX_BLOCK = "regex_block"
    REGEX_REQUIRE = "regex_require"
    PII_DETECT = "pii_detect"
    ENTITLEMENT = "entitlement"


@dataclass(frozen=True)
class ToolCall:
    """Framework-agnostic representation of an agent tool call."""

    name: str
    args: dict[str, Any]
    call_id: str = ""
    user_id: str = ""
    request_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleConfig:
    """A single rule parsed from config."""

    name: str
    rule_type: RuleType
    params: dict[str, Any]
    applies_to: list[str]  # tool name patterns, ["*"] = all
    phase: str = "pre"  # "pre" or "post"


@dataclass
class RuleResult:
    """Result of evaluating a single rule against a tool call."""

    rule_name: str
    rule_type: str
    decision: Decision
    reason: str
    matched_value: str | None = None


@dataclass
class EvalResult:
    """Aggregate result of evaluating all rules against a tool call."""

    decision: Decision
    tool_call: ToolCall
    rules_evaluated: list[RuleResult]
    blocking_rule: RuleResult | None = None
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def reason(self) -> str:
        if self.blocking_rule:
            return self.blocking_rule.reason
        return "All rules passed"


class ToolCallBlocked(Exception):
    """Raised when a tool call is blocked by a rule."""

    def __init__(self, result: EvalResult):
        self.result = result
        rule = result.blocking_rule
        super().__init__(
            f"Tool call '{result.tool_call.name}' blocked by rule "
            f"'{rule.rule_name}': {rule.reason}" if rule else "Blocked"
        )
