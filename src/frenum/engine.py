"""Core evaluation engine for frenum."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from frenum._types import (
    CoverageReport,
    Decision,
    EvalResult,
    RuleConfig,
    RuleKind,
    RuleResult,
    TestCaseConfig,
    TestResult,
    ToolCall,
    ToolCallBlocked,
)
from frenum.rules import get_handler


class Engine:
    """Deterministic rule engine for tool call evaluation.

    Rules are evaluated in order. First BLOCK wins (short-circuit).
    Semantic rules are skipped during evaluation.
    No LLM calls — every decision is reproducible.
    """

    def __init__(
        self,
        rules: list[RuleConfig] | None = None,
        *,
        audit_logger: Callable[[EvalResult], Any] | None = None,
        policy_version: str = "1.0.0",
    ):
        self._rules = rules or []
        self._audit_logger = audit_logger
        self.policy_version = policy_version

    @property
    def rules(self) -> list[RuleConfig]:
        return list(self._rules)

    @classmethod
    def from_yaml(cls, path: str | Path, **kwargs: Any) -> Engine:
        """Load engine from a YAML config file."""
        from frenum.loader import load_policy

        rules, policy_version = load_policy(path)
        return cls(rules, policy_version=policy_version, **kwargs)

    @classmethod
    def from_dict(cls, config: dict[str, Any], **kwargs: Any) -> Engine:
        """Load engine from a Python dict (same schema as YAML)."""
        from frenum.loader import load_policy_dict

        rules = load_policy_dict(config)
        policy_version = config.get("policy_version", "1.0.0")
        return cls(rules, policy_version=policy_version, **kwargs)

    def evaluate(
        self, tool_call: ToolCall, phase: str = "pre",
    ) -> EvalResult:
        """Evaluate all applicable deterministic rules. First BLOCK short-circuits."""
        results: list[RuleResult] = []
        blocking_rule: RuleResult | None = None

        for rule in self._rules:
            if rule.kind == RuleKind.SEMANTIC:
                continue
            if rule.phase != phase:
                continue
            if not self._rule_applies(rule, tool_call):
                continue

            handler = get_handler(rule.rule_type)
            result = handler(rule, tool_call)
            results.append(result)

            if result.decision == Decision.BLOCK:
                blocking_rule = result
                break

        decision = Decision.BLOCK if blocking_rule else Decision.ALLOW
        eval_result = EvalResult(
            decision=decision,
            tool_call=tool_call,
            rules_evaluated=results,
            blocking_rule=blocking_rule,
        )

        if self._audit_logger:
            self._audit_logger(eval_result)

        return eval_result

    def guard(self, tool_call: ToolCall, phase: str = "pre") -> ToolCall:
        """Evaluate and raise ToolCallBlocked on block."""
        result = self.evaluate(tool_call, phase)
        if result.decision == Decision.BLOCK:
            raise ToolCallBlocked(result)
        return tool_call

    def run_tests(
        self, test_cases: list[TestCaseConfig],
    ) -> list[TestResult]:
        """Run all test cases against the policy rules."""
        results: list[TestResult] = []
        for tc in test_cases:
            eval_result = self.evaluate(tc.tool_call)
            passed = eval_result.decision == tc.expected
            actual_rule = (
                eval_result.blocking_rule.rule_name
                if eval_result.blocking_rule else None
            )
            reason = eval_result.reason

            if tc.expected_rule and passed:
                if actual_rule != tc.expected_rule:
                    passed = False
                    reason = (
                        f"Expected rule '{tc.expected_rule}', "
                        f"got '{actual_rule}'"
                    )
            if not passed and not tc.expected_rule:
                reason = (
                    f"Expected {tc.expected.value}, "
                    f"got {eval_result.decision.value}: {eval_result.reason}"
                )

            results.append(TestResult(
                test_case=tc,
                actual=eval_result.decision,
                actual_rule=actual_rule,
                passed=passed,
                reason=reason,
                rules_evaluated=eval_result.rules_evaluated_names,
            ))
        return results

    def calculate_coverage(
        self, results: list[TestResult],
    ) -> CoverageReport:
        """Calculate guardrail coverage from test results."""
        deterministic = [
            r for r in self._rules if r.kind == RuleKind.DETERMINISTIC
        ]
        semantic = [
            r for r in self._rules if r.kind == RuleKind.SEMANTIC
        ]
        det_names = {r.name for r in deterministic}

        exercised: set[str] = set()
        for r in results:
            exercised.update(r.rules_evaluated)

        covered = exercised & det_names
        not_covered = det_names - covered
        pct = (len(covered) / len(det_names) * 100) if det_names else 100.0

        return CoverageReport(
            total_deterministic_rules=len(det_names),
            rules_exercised=sorted(covered),
            rules_not_exercised=sorted(not_covered),
            semantic_rules=[r.name for r in semantic],
            coverage_pct=round(pct, 1),
        )

    def _rule_applies(self, rule: RuleConfig, tool_call: ToolCall) -> bool:
        for pattern in rule.applies_to:
            if pattern == "*" or re.fullmatch(pattern, tool_call.name):
                return True
        return False
