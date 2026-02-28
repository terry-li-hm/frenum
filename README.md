# frenum

> Guardrail lifecycle for LLM agent tool calls.
> Define. Lint. Enforce. Test. Measure. Audit.

Named after the Latin word for *bridle* or *restraint*. The rein that keeps your LLM agent in check.

## Why

LLM agents call tools autonomously — execute SQL, send emails, make API calls. Teams are shipping guardrails, but the lifecycle around them is fragmented: enforcement in one tool, testing cobbled together with pytest, audit as an afterthought, policy definitions scattered across code and config.

frenum puts the full guardrail lifecycle under one YAML schema:

```
policy.yaml  →  frenum lint   →  Engine.evaluate()  →  frenum test  →  coverage %  →  audit.jsonl
   Define          Lint              Enforce               Test          Measure         Audit
```

- **YAML config** — rules live in config files that compliance teams can review, version, and audit
- **Zero-LLM enforcement** — every decision is deterministic and reproducible
- **Guardrail coverage** — know exactly which rules are tested and which aren't
- **Policy linting** — catch broken regex and missing params before deployment
- **Compliance-first** — OPA-inspired audit trail with PII redaction
- **Framework-agnostic** — works standalone or with LangGraph

## Quick Start

```bash
pip install frenum[yaml]
```

```python
from frenum import Engine, ToolCall

engine = Engine.from_yaml("policy.yaml")

result = engine.evaluate(
    ToolCall(name="execute_sql", args={"query": "DROP TABLE users"})
)
print(result.decision)  # Decision.BLOCK
print(result.reason)    # "Pattern matched in 'query': DROP TABLE"
```

## CLI

### Regression Testing

```bash
frenum test --config policy.yaml --tests tests/ --format text
```

```
frenum — guardrail regression test report
==================================================
Results: 5/5 passed, 0 failed

  [PASS] SQL injection blocked
  [PASS] Clean query allowed
  [PASS] PII in email body blocked
  [PASS] Admin can call any tool
  [PASS] Analyst blocked from execute_sql

Coverage: 100.0% (4/4 deterministic rules)
  Semantic (manual validation required): tone_check

Evidence hash: a3f8c1d2e5b7...
```

Exit code 0 = all pass, 1 = failures. CI-ready.

### Policy Linting

```bash
frenum lint --config policy.yaml
```

```
  ERROR E001 [bad_regex]: Invalid regex pattern '[a-z': unterminated character set
  ERROR E002 [pii_scan]: Unknown PII detector: 'passport'
  WARN  W002 [incomplete]: Missing required parameter 'patterns' for rule type 'regex_block'

2 error(s), 1 warning(s)
```

Exit code 0 = clean, 1 = errors found.

## YAML Config

```yaml
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
      detectors: [email, phone_intl, hk_id, credit_card, ssn]
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

  # Cost threshold
  - name: budget_limit
    type: budget
    applies_to: ["*"]
    params:
      max_cost: 10.0
      cost_field: estimated_cost

  # Tool allowlist
  - name: allowed_tools_only
    type: tool_allowlist
    applies_to: ["*"]
    params:
      allowed_tools: ["search", "get_data", "summarize", "execute_sql"]

  # Semantic rules are tracked but not enforced in CI
  - name: tone_check
    type: regex_block
    kind: semantic
    applies_to: ["*"]
    params:
      fields: ["response"]
      patterns: ["placeholder"]
```

## Test Cases

```yaml
tests:
  - description: SQL injection blocked
    tool_call:
      name: execute_sql
      args:
        query: "DROP TABLE users"
    expected: block
    expected_rule: block_sql_injection

  - description: Clean query allowed
    tool_call:
      name: execute_sql
      args:
        query: "SELECT * FROM users WHERE id = 1"
    expected: allow

  - description: PII in email body blocked
    tool_call:
      name: send_email
      args:
        body: "Customer HKID is A123456(7)"
    expected: block
```

## Rule Types

| Type | Purpose | Key Params |
|---|---|---|
| `regex_block` | Block if field matches pattern | `fields`, `patterns` |
| `regex_require` | Block if required field is missing/invalid | `fields`, `pattern` |
| `pii_detect` | Scan args for PII (email, phone, HKID, credit card, SSN) | `detectors`, `action` |
| `entitlement` | Role-based tool access control | `roles`, `default` |
| `budget` | Block if estimated cost exceeds threshold | `max_cost`, `cost_field` |
| `tool_allowlist` | Block tools not in allowed list | `allowed_tools` |

## Guardrail Coverage

```
guardrail coverage = rules_exercised / total_deterministic_rules
```

Rules tagged `kind: semantic` are excluded from the denominator and listed as "manual validation required" in every report. Honest boundaries over inflated numbers.

```python
engine = Engine.from_yaml("policy.yaml")
results = engine.run_tests(test_cases)
coverage = engine.calculate_coverage(results)
print(f"Coverage: {coverage.coverage_pct}%")
print(f"Not exercised: {coverage.rules_not_exercised}")
print(f"Semantic (manual): {coverage.semantic_rules}")
```

## Policy Linting

Catch config errors before deployment:

| Code | Severity | What it catches |
|------|----------|----------------|
| E001 | Error | Invalid regex pattern |
| E002 | Error | Unknown PII detector name |
| E003 | Error | Duplicate rule names |
| W001 | Warning | Empty `applies_to` (rule will never match) |
| W002 | Warning | Missing required parameters for rule type |
| W003 | Warning | Unknown rule type |

```python
from frenum import lint_policy

warnings = lint_policy(engine.rules)
for w in warnings:
    print(f"{w.severity.upper()} {w.code} [{w.rule_name}]: {w.message}")
```

## Audit Trail

Every evaluation produces a structured JSONL record with PII redaction:

```python
from frenum import AuditLogger, Engine

logger = AuditLogger("audit.jsonl", redact_args=True)
engine = Engine.from_yaml("policy.yaml", audit_logger=logger.log)
```

Each record includes: `decision_id`, `timestamp`, `policy_version`, `tool_name`, `tool_args` (redacted), `decision`, `rules_evaluated`, `blocking_rule`, `human_override`, `trace_id`.

### Audit Reports

```python
from frenum import AuditReporter

reporter = AuditReporter("audit.jsonl")
report = reporter.generate()
print(report.to_text())
```

```
========================================
FRENUM AUDIT REPORT
========================================
Total evaluations: 500
       Allow:    450 (90.0%)
       Block:     50 (10.0%)

Top blocked tools:
  1. execute_sql                    — 25 blocks
  2. send_email                     — 15 blocks

Human override rate: 4.0% (2 of 50 blocks overridden)
========================================
```

## Reports

Test reports in three formats:

```bash
frenum test --config policy.yaml --tests tests/ --format json --output report.json
frenum test --config policy.yaml --tests tests/ --format html --output report.html
```

HTML reports include a coverage bar, pass/fail matrix, and SHA-256 evidence hashing for tamper-evidence. Install `frenum[html]` for Jinja2 templates; stdlib fallback works without it.

## LangGraph Integration

```bash
pip install frenum[langgraph]
```

```python
from langgraph.prebuilt import ToolNode
from frenum import Engine
from frenum.adapters.langgraph import guarded_tool_node

tools = [search, calculator]
engine = Engine.from_yaml("policy.yaml")
safe_tools = guarded_tool_node(ToolNode(tools), engine)

builder.add_node("tools", safe_tools)
```

Blocked tool calls return a `ToolMessage` with the block reason — the LLM sees why its call was rejected and can adjust. Each tool call in a multi-call message is evaluated independently.

## Programmatic Use (No YAML)

```python
from frenum import Engine, RuleConfig, ToolCall

engine = Engine(rules=[
    RuleConfig(
        name="block_drops",
        rule_type="regex_block",
        params={"fields": ["query"], "patterns": [r"(?i)DROP\s+TABLE"]},
        applies_to=["execute_sql"],
    ),
])

result = engine.evaluate(ToolCall(name="execute_sql", args={"query": "SELECT 1"}))
assert result.decision.value == "allow"
```

Zero dependencies — the core engine runs on stdlib alone. YAML loading, HTML reports, and LangGraph are optional extras.

## Design Philosophy

- **Config is reviewable.** Compliance teams review YAML, not Python.
- **No LLM in the enforcement path.** Every decision is deterministic and reproducible.
- **First BLOCK wins.** Short-circuit evaluation matches firewall semantics that security teams already know.
- **Honest about limits.** Semantic rules can't be tested deterministically, so they're carved out explicitly.
- **Lint before deploy.** Catch policy config errors at authoring time, not at runtime.
- **Audit everything.** Every decision is logged with enough context to investigate, but matched values are redacted.

## License

MIT
