"""Tests for the audit logger."""

import json
from io import StringIO

from frenum import AuditLogger, Engine, ToolCall


class TestAuditLogger:
    def test_writes_jsonl_line(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        engine = Engine(audit_logger=logger.log)

        call = ToolCall(name="search", args={"query": "test"})
        engine.evaluate(call)

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["decision"] == "allow"
        assert record["tool_name"] == "search"

    def test_multiple_writes(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        engine = Engine(audit_logger=logger.log)

        for i in range(3):
            engine.evaluate(ToolCall(name=f"tool_{i}", args={}))

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_stream_logging(self):
        stream = StringIO()
        logger = AuditLogger(stream=stream)
        engine = Engine(audit_logger=logger.log)

        call = ToolCall(name="search", args={"query": "test"})
        engine.evaluate(call)

        output = stream.getvalue()
        record = json.loads(output.strip())
        assert record["decision"] == "allow"

    def test_redaction(self, tmp_path, regex_block_rule):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        engine = Engine(rules=[regex_block_rule], audit_logger=logger.log)

        call = ToolCall(name="execute_sql", args={"query": "DROP TABLE users"})
        engine.evaluate(call)

        record = json.loads(log_path.read_text().strip())
        # The matched value should be redacted in the args
        assert "***" in record["tool_args"]["query"]

    def test_parseable_json(self, tmp_path, regex_block_rule):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        engine = Engine(rules=[regex_block_rule], audit_logger=logger.log)

        engine.evaluate(ToolCall(name="execute_sql", args={"query": "DROP TABLE x"}))
        engine.evaluate(ToolCall(name="execute_sql", args={"query": "SELECT 1"}))

        for line in log_path.read_text().strip().split("\n"):
            record = json.loads(line)
            assert "decision_id" in record
            assert "timestamp" in record
            assert "decision" in record

    def test_record_has_required_fields(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, policy_version="2.0.0")
        engine = Engine(audit_logger=logger.log)

        call = ToolCall(name="test", args={}, user_id="user-1", request_id="req-1")
        engine.evaluate(call)

        record = json.loads(log_path.read_text().strip())
        assert record["policy_version"] == "2.0.0"
        assert record["user_id"] == "user-1"
        assert record["request_id"] == "req-1"
        assert record["human_override"] is None
        assert "rules_evaluated" in record
