"""Audit logger for limen — append-only JSONL decision records."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import IO, Any

from limen._types import EvalResult


class AuditLogger:
    """Append-only JSONL audit logger.

    Each evaluation produces one JSON line with OPA-inspired fields.
    Sensitive values in tool args are automatically redacted.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        stream: IO[str] | None = None,
        redact_args: bool = True,
        policy_version: str = "1.0.0",
    ):
        self._path = Path(path) if path else None
        self._stream = stream
        self._redact_args = redact_args
        self.policy_version = policy_version

        if self._path is None and self._stream is None:
            self._stream = sys.stdout

    def log(self, result: EvalResult) -> dict[str, Any]:
        """Serialize and append an EvalResult. Returns the record dict."""
        record = self._to_record(result)
        line = json.dumps(record, default=str, ensure_ascii=False)

        if self._path:
            with self._path.open("a") as f:
                f.write(line + "\n")

        if self._stream:
            self._stream.write(line + "\n")
            self._stream.flush()

        return record

    def _to_record(self, result: EvalResult) -> dict[str, Any]:
        """Convert an EvalResult to an audit record dict."""
        # Collect matched values for redaction
        matched_values: set[str] = set()
        for r in result.rules_evaluated:
            if r.matched_value:
                matched_values.add(r.matched_value.rstrip("*"))

        tool_args = result.tool_call.args
        if self._redact_args and matched_values:
            tool_args = self._redact_dict(tool_args, matched_values)

        return {
            "decision_id": result.decision_id,
            "timestamp": result.timestamp.isoformat(),
            "policy_version": self.policy_version,
            "decision": result.decision.value,
            "tool_name": result.tool_call.name,
            "tool_args": tool_args,
            "user_id": result.tool_call.user_id,
            "request_id": result.tool_call.request_id,
            "rules_evaluated": [
                {
                    "rule_name": r.rule_name,
                    "rule_type": r.rule_type,
                    "decision": r.decision.value,
                    "reason": r.reason,
                }
                for r in result.rules_evaluated
            ],
            "blocking_rule": result.blocking_rule.rule_name if result.blocking_rule else None,
            "human_override": None,
            "trace_id": result.tool_call.metadata.get("trace_id"),
        }

    def _redact_dict(self, d: dict[str, Any], matched: set[str]) -> dict[str, Any]:
        """Redact values that contain matched strings."""
        redacted: dict[str, Any] = {}
        for k, v in d.items():
            if isinstance(v, str):
                redacted[k] = self._redact_value(v, matched)
            elif isinstance(v, dict):
                redacted[k] = self._redact_dict(v, matched)
            elif isinstance(v, list):
                redacted[k] = [
                    self._redact_value(item, matched) if isinstance(item, str) else item
                    for item in v
                ]
            else:
                redacted[k] = v
        return redacted

    def _redact_value(self, value: str, matched: set[str]) -> str:
        """Redact a string if it contains any matched value."""
        for m in matched:
            if m in value:
                return value[:10] + "***"
        return value
