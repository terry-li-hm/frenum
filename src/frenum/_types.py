"""Core types for frenum — guardrail lifecycle for LLM agent tool calls."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"


class RuleKind(Enum):
    DETERMINISTIC = "deterministic"
    SEMANTIC = "semantic"


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
    """A single rule from the policy config."""

    name: str
    rule_type: str  # regex_block, regex_require, pii_detect, entitlement, budget, tool_allowlist
    params: dict[str, Any]
    applies_to: list[str]  # tool name patterns, ["*"] = all
    kind: RuleKind = RuleKind.DETERMINISTIC
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

    @property
    def rules_evaluated_names(self) -> list[str]:
        return [r.rule_name for r in self.rules_evaluated]


class ToolCallBlocked(Exception):
    """Raised when a tool call is blocked by a rule."""

    def __init__(self, result: EvalResult):
        self.result = result
        rule = result.blocking_rule
        super().__init__(
            f"Tool call '{result.tool_call.name}' blocked by rule "
            f"'{rule.rule_name}': {rule.reason}" if rule else "Blocked"
        )


# ---------------------------------------------------------------------------
# Testing types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestCaseConfig:
    """A single test case: tool call + expected verdict."""

    description: str
    tool_call: ToolCall
    expected: Decision
    expected_rule: str | None = None


@dataclass
class TestResult:
    """Result of running one test case."""

    test_case: TestCaseConfig
    actual: Decision
    actual_rule: str | None
    passed: bool
    reason: str
    rules_evaluated: list[str] = field(default_factory=list)


@dataclass
class CoverageReport:
    """Guardrail coverage: how many deterministic rules were exercised."""

    total_deterministic_rules: int
    rules_exercised: list[str]
    rules_not_exercised: list[str]
    semantic_rules: list[str]
    coverage_pct: float


@dataclass
class LintWarning:
    """A single warning or error from policy linting."""

    rule_name: str | None
    code: str
    message: str
    severity: str  # "error" or "warning"
