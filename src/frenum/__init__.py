"""frenum — Deterministic, config-driven guardrails for LLM agent tool calls.

Named after the Latin word for 'bridle' or 'restraint'.
The rein that keeps your LLM agent in check.
"""

from frenum._types import Decision, EvalResult, RuleConfig, RuleResult, ToolCall, ToolCallBlocked
from frenum.audit import AuditLogger
from frenum.engine import Engine
from frenum.reporter import AuditReporter, Report

__version__ = "0.1.0"

__all__ = [
    "AuditLogger",
    "AuditReporter",
    "Decision",
    "Engine",
    "EvalResult",
    "Report",
    "RuleConfig",
    "RuleResult",
    "ToolCall",
    "ToolCallBlocked",
]
