"""obex — Deterministic, config-driven guardrails for LLM agent tool calls.

Named after the Latin word for 'bolt' or 'barrier'.
The bolt on the gate that no LLM can argue past.
"""

from obex._types import Decision, EvalResult, RuleConfig, RuleResult, ToolCall, ToolCallBlocked
from obex.audit import AuditLogger
from obex.engine import Engine
from obex.reporter import AuditReporter, Report

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
