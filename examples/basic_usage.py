"""Basic usage of limen — evaluate tool calls against YAML rules."""

from limen import AuditLogger, AuditReporter, Engine, ToolCall

# Load rules from YAML config
engine = Engine.from_yaml("examples/config.yaml", audit_logger=AuditLogger("audit.jsonl").log)

# A safe query by an authorized user — passes through
safe = ToolCall(
    name="execute_sql",
    args={"query": "SELECT * FROM users WHERE id = 1"},
    metadata={"role": "operator"},
)
result = engine.evaluate(safe)
print(f"Safe query:  {result.decision.value}")  # allow

# A dangerous query — blocked by regex rule
dangerous = ToolCall(
    name="execute_sql",
    args={"query": "DROP TABLE users"},
    metadata={"role": "operator"},
)
result = engine.evaluate(dangerous)
print(f"DROP TABLE:  {result.decision.value}")  # block
print(f"  Reason:    {result.reason}")

# PII in arguments — blocked
pii = ToolCall(
    name="search",
    args={"query": "Contact alice@example.com"},
    metadata={"role": "analyst"},
)
result = engine.evaluate(pii)
print(f"PII leak:    {result.decision.value}")  # block
print(f"  Reason:    {result.reason}")

# Unauthorized tool access — analyst can't run SQL
unauthorized = ToolCall(
    name="execute_sql",
    args={"query": "SELECT 1"},
    metadata={"role": "analyst"},
)
result = engine.evaluate(unauthorized)
print(f"Unauthed:    {result.decision.value}")  # block
print(f"  Reason:    {result.reason}")

# Generate audit report
print()
reporter = AuditReporter("audit.jsonl")
report = reporter.generate()
print(report.to_text())
