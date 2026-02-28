# frenum

> Deterministic, config-driven guardrails for LLM agent tool calls.
> Zero-LLM enforcement. Compliance audit trail built in.

Named after the Latin word for *bridle* or *restraint*. The rein that keeps your LLM agent in check.

## Why

LLM agents can now call tools autonomously — execute SQL, send emails, make API calls. Existing guardrail frameworks either use LLM calls in the enforcement path (non-deterministic, slow, expensive) or require writing Python code that compliance teams can't review.

Frenum is different:

- **YAML config** — rules live in config files that compliance teams can review, version, and audit without reading Python
- **Zero-LLM enforcement** — every decision is deterministic and reproducible. No AI in the guardrail path.
- **Compliance-first** — OPA-inspired audit trail as a first-class feature, not an afterthought
- **Framework-agnostic** — works standalone or with LangGraph, CrewAI, or any agent framework

| Feature | Frenum | NeMo Guardrails | LangChain Middleware | OpenAI Agents SDK |
|---|---|---|---|---|
| Config-driven (YAML) | Yes | Colang DSL | Python code | Python decorators |
| Zero-LLM enforcement | Yes | No (LLM in loop) | Yes | Yes |
| Audit trail | Built-in | Logging only | No | No |
| Framework-agnostic | Yes | LangChain | LangChain only | OpenAI only |
| Dependencies | Zero (stdlib) | Heavy | LangChain | OpenAI SDK |

## Quick Start

```bash
pip install frenum[yaml]
```

```python
from frenum import Engine, ToolCall

engine = Engine.from_yaml("rules.yaml")

# Evaluate a tool call
result = engine.evaluate(
    ToolCall(name="execute_sql", args={"query": "DROP TABLE users"})
)
print(result.decision)  # Decision.BLOCK
print(result.reason)    # "Pattern matched in field 'query': DROP TABLE"
```

## YAML Config

```yaml
version: "1.0"
policy_version: "1.0.0"

rules:
  # Block dangerous SQL patterns
  - name: block_sql_injection
    type: regex_block
    applies_to: ["execute_sql", "run_query"]
    params:
      fields: ["query"]
      patterns:
        - "(?i)(DROP|DELETE|TRUNCATE)\\s+TABLE"

  # Require confirmation IDs on sensitive operations
  - name: require_confirmation
    type: regex_require
    applies_to: ["send_email", "transfer_funds"]
    params:
      fields: ["confirmation_id"]
      pattern: "^CONF-[A-Z0-9]{8}$"

  # Scan all tool calls for PII leakage
  - name: detect_pii
    type: pii_detect
    applies_to: ["*"]
    params:
      detectors: [email, phone_intl, hk_id, credit_card]
      action: block

  # Role-based tool access
  - name: tool_entitlement
    type: entitlement
    applies_to: ["*"]
    params:
      roles:
        analyst: ["search", "get_data", "summarize"]
        admin: ["*"]
      default: block
```

### Rule Types

| Type | Purpose | Key Params |
|---|---|---|
| `regex_block` | Block if field matches pattern | `fields`, `patterns` |
| `regex_require` | Block if required field is missing/invalid | `fields`, `pattern` |
| `pii_detect` | Scan args for PII (email, phone, HKID, etc.) | `detectors`, `action` |
| `entitlement` | Role-based tool access control | `roles`, `default` |

## Audit Trail

Every evaluation produces a structured JSON record (JSONL format, OPA-inspired):

```python
from frenum import AuditLogger, Engine

logger = AuditLogger("audit.jsonl")
engine = Engine.from_yaml("rules.yaml", audit_logger=logger.log)
```

Each record includes: `decision_id`, `timestamp`, `policy_version`, `tool_name`, `tool_args` (redacted), `decision`, `rules_evaluated`, `blocking_rule`, `human_override`, `trace_id`.

## Audit Reports

Generate compliance-ready summaries from audit logs:

```python
from frenum import AuditReporter

reporter = AuditReporter("audit.jsonl")
report = reporter.generate()
print(report.to_text())
```

```
========================================
OBEX AUDIT REPORT
========================================
Period: 2026-02-28 10:00 to 2026-02-28 16:00
Policy versions: 1.0.0

Total evaluations: 500
       Allow:    450 (90.0%)
       Block:     50 (10.0%)

Top blocked tools:
  1. execute_sql                    — 25 blocks
  2. send_email                     — 15 blocks

Top triggered rules:
  1. block_sql_injection            — 20 triggers
  2. detect_pii                     — 18 triggers

Human override rate: 4.0% (2 of 50 blocks overridden)
========================================
```

## LangGraph Integration

```bash
pip install frenum[langgraph]
```

```python
from langgraph.prebuilt import ToolNode
from frenum import Engine
from frenum.adapters.langgraph import guarded_tool_node

tools = [search, calculator]
engine = Engine.from_yaml("rules.yaml")
safe_tools = guarded_tool_node(ToolNode(tools), engine)

builder.add_node("tools", safe_tools)
```

Blocked tool calls return a `ToolMessage` with the block reason — the LLM sees why its call was rejected and can adjust.

## Programmatic Use (No YAML)

```python
from frenum import Engine, ToolCall
from frenum._types import RuleConfig, RuleType

engine = Engine(rules=[
    RuleConfig(
        name="block_drops",
        rule_type=RuleType.REGEX_BLOCK,
        params={"fields": ["query"], "patterns": [r"(?i)DROP\s+TABLE"]},
        applies_to=["execute_sql"],
    ),
])

result = engine.evaluate(ToolCall(name="execute_sql", args={"query": "SELECT 1"}))
assert result.decision.value == "allow"
```

Zero dependencies — the core engine runs on stdlib alone.

## Design Philosophy

- **Hooks > prompts** for mechanical rules. If a rule is regex-matchable, enforce it in code, not in the system prompt.
- **Fail closed.** If a rule errors, the tool call is blocked.
- **No LLM in the enforcement path.** Every decision is deterministic and reproducible.
- **Config is reviewable.** Compliance teams review YAML, not Python.
- **Audit schema inspired by OPA.** Decision logs follow established policy-engine conventions.

## License

MIT
