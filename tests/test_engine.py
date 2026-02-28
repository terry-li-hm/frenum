"""Tests for the core engine."""

import pytest

from limen import Decision, Engine, ToolCall, ToolCallBlocked


class TestEngineBasics:
    def test_empty_rules_allow_all(self, simple_tool_call):
        engine = Engine()
        result = engine.evaluate(simple_tool_call)
        assert result.decision == Decision.ALLOW

    def test_from_dict_loads_rules(self, sample_config, dangerous_tool_call):
        engine = Engine.from_dict(sample_config)
        result = engine.evaluate(dangerous_tool_call)
        assert result.decision == Decision.BLOCK

    def test_from_dict_invalid_rule_type(self):
        config = {"rules": [{"name": "bad", "type": "nonexistent", "params": {}}]}
        with pytest.raises(ValueError, match="Unknown rule type"):
            Engine.from_dict(config)

    def test_policy_version_from_config(self, sample_config):
        engine = Engine.from_dict(sample_config)
        assert engine.policy_version == "1.0.0"


class TestEvaluation:
    def test_first_block_short_circuits(self, sample_config):
        engine = Engine.from_dict(sample_config)
        call = ToolCall(name="execute_sql", args={"query": "DROP TABLE users"})
        result = engine.evaluate(call)
        assert result.decision == Decision.BLOCK
        # Only the first rule should have been evaluated (short-circuit)
        assert len(result.rules_evaluated) == 1
        assert result.blocking_rule is not None
        assert result.blocking_rule.rule_name == "block_sql_injection"

    def test_clean_query_passes(self, sample_config, simple_tool_call):
        engine = Engine.from_dict(sample_config)
        result = engine.evaluate(simple_tool_call)
        assert result.decision == Decision.ALLOW

    def test_rule_applies_wildcard(self, pii_rule):
        engine = Engine(rules=[pii_rule])
        call = ToolCall(name="any_tool", args={"data": "email: test@test.com"})
        result = engine.evaluate(call)
        assert result.decision == Decision.BLOCK

    def test_rule_applies_specific_tool(self, regex_block_rule):
        engine = Engine(rules=[regex_block_rule])
        # Different tool name — rule should not apply
        call = ToolCall(name="other_tool", args={"query": "DROP TABLE users"})
        result = engine.evaluate(call)
        assert result.decision == Decision.ALLOW

    def test_decision_id_is_set(self, simple_tool_call):
        engine = Engine()
        result = engine.evaluate(simple_tool_call)
        assert result.decision_id
        assert len(result.decision_id) == 12

    def test_timestamp_is_set(self, simple_tool_call):
        engine = Engine()
        result = engine.evaluate(simple_tool_call)
        assert result.timestamp is not None


class TestGuard:
    def test_guard_returns_tool_call_on_allow(self, simple_tool_call):
        engine = Engine()
        returned = engine.guard(simple_tool_call)
        assert returned is simple_tool_call

    def test_guard_raises_on_block(self, regex_block_rule, dangerous_tool_call):
        engine = Engine(rules=[regex_block_rule])
        with pytest.raises(ToolCallBlocked) as exc_info:
            engine.guard(dangerous_tool_call)
        assert exc_info.value.result.decision == Decision.BLOCK


class TestAuditCallback:
    def test_audit_callback_called(self, simple_tool_call):
        results = []
        engine = Engine(audit_logger=results.append)
        engine.evaluate(simple_tool_call)
        assert len(results) == 1
        assert results[0].decision == Decision.ALLOW

    def test_audit_callback_on_block(self, regex_block_rule, dangerous_tool_call):
        results = []
        engine = Engine(rules=[regex_block_rule], audit_logger=results.append)
        engine.evaluate(dangerous_tool_call)
        assert len(results) == 1
        assert results[0].decision == Decision.BLOCK
