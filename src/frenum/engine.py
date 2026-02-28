"""Core evaluation engine for frenum."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from frenum._types import (
    Decision,
    EvalResult,
    RuleConfig,
    RuleResult,
    RuleType,
    ToolCall,
    ToolCallBlocked,
)
from frenum.rules import get_handler


class Engine:
    """Deterministic rule engine for tool call evaluation.

    Rules are evaluated in order. First BLOCK wins (short-circuit).
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

    @classmethod
    def from_yaml(cls, path: str | Path, **kwargs: Any) -> Engine:
        """Load engine from a YAML config file.

        Requires pyyaml: pip install frenum[yaml]
        """
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "pyyaml is required for YAML config loading. "
                "Install it with: pip install frenum[yaml]"
            ) from None

        path = Path(path)
        with path.open() as f:
            config = yaml.safe_load(f)

        return cls.from_dict(config, **kwargs)

    @classmethod
    def from_dict(cls, config: dict[str, Any], **kwargs: Any) -> Engine:
        """Load engine from a Python dict (same schema as YAML)."""
        rules: list[RuleConfig] = []
        policy_version = config.get("policy_version", "1.0.0")

        for rule_data in config.get("rules", []):
            try:
                rule_type = RuleType(rule_data["type"])
            except ValueError:
                raise ValueError(
                    f"Unknown rule type: {rule_data['type']}. "
                    f"Valid types: {[rt.value for rt in RuleType]}"
                ) from None

            rules.append(
                RuleConfig(
                    name=rule_data["name"],
                    rule_type=rule_type,
                    params=rule_data.get("params", {}),
                    applies_to=rule_data.get("applies_to", ["*"]),
                    phase=rule_data.get("phase", "pre"),
                )
            )

        return cls(rules, policy_version=policy_version, **kwargs)

    def evaluate(self, tool_call: ToolCall, phase: str = "pre") -> EvalResult:
        """Evaluate all applicable rules against a tool call.

        First blocking rule short-circuits. Returns EvalResult.
        """
        results: list[RuleResult] = []
        blocking_rule: RuleResult | None = None

        for rule in self._rules:
            if rule.phase != phase:
                continue
            if not self._rule_applies(rule, tool_call):
                continue

            handler = get_handler(rule.rule_type)
            result = handler(rule, tool_call)
            results.append(result)

            if result.decision == Decision.BLOCK:
                blocking_rule = result
                break  # Short-circuit: first block wins

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
        """Evaluate and raise on block. Convenience for try/except patterns."""
        result = self.evaluate(tool_call, phase)
        if result.decision == Decision.BLOCK:
            raise ToolCallBlocked(result)
        return tool_call

    def _rule_applies(self, rule: RuleConfig, tool_call: ToolCall) -> bool:
        """Check if a rule applies to this tool call."""
        for pattern in rule.applies_to:
            if pattern == "*" or re.fullmatch(pattern, tool_call.name):
                return True
        return False
