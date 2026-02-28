"""Tests for built-in rule implementations."""

from frenum import Decision, ToolCall
from frenum.rules import eval_entitlement, eval_pii_detect, eval_regex_block, eval_regex_require


class TestRegexBlock:
    def test_matches_drop_table(self, regex_block_rule, dangerous_tool_call):
        result = eval_regex_block(regex_block_rule, dangerous_tool_call)
        assert result.decision == Decision.BLOCK
        assert "DROP TABLE" in result.reason

    def test_clean_query_passes(self, regex_block_rule, simple_tool_call):
        result = eval_regex_block(regex_block_rule, simple_tool_call)
        assert result.decision == Decision.ALLOW

    def test_case_insensitive(self, regex_block_rule):
        call = ToolCall(name="execute_sql", args={"query": "drop table users"})
        result = eval_regex_block(regex_block_rule, call)
        assert result.decision == Decision.BLOCK

    def test_missing_field_passes(self, regex_block_rule):
        call = ToolCall(name="execute_sql", args={"other": "DROP TABLE"})
        result = eval_regex_block(regex_block_rule, call)
        assert result.decision == Decision.ALLOW


class TestRegexRequire:
    def test_present_and_valid(self):
        from frenum._types import RuleConfig, RuleType

        rule = RuleConfig(
            name="require_confirmation",
            rule_type=RuleType.REGEX_REQUIRE,
            params={"fields": ["confirmation_id"], "pattern": r"^CONF-[A-Z0-9]{8}$"},
            applies_to=["*"],
        )
        call = ToolCall(name="transfer", args={"confirmation_id": "CONF-AB12CD34"})
        result = eval_regex_require(rule, call)
        assert result.decision == Decision.ALLOW

    def test_missing_field_blocks(self):
        from frenum._types import RuleConfig, RuleType

        rule = RuleConfig(
            name="require_confirmation",
            rule_type=RuleType.REGEX_REQUIRE,
            params={"fields": ["confirmation_id"], "pattern": r"^CONF-[A-Z0-9]{8}$"},
            applies_to=["*"],
        )
        call = ToolCall(name="transfer", args={"amount": 100})
        result = eval_regex_require(rule, call)
        assert result.decision == Decision.BLOCK
        assert "missing" in result.reason

    def test_invalid_format_blocks(self):
        from frenum._types import RuleConfig, RuleType

        rule = RuleConfig(
            name="require_confirmation",
            rule_type=RuleType.REGEX_REQUIRE,
            params={"fields": ["confirmation_id"], "pattern": r"^CONF-[A-Z0-9]{8}$"},
            applies_to=["*"],
        )
        call = ToolCall(name="transfer", args={"confirmation_id": "WRONG-FORMAT"})
        result = eval_regex_require(rule, call)
        assert result.decision == Decision.BLOCK
        assert "does not match" in result.reason


class TestPiiDetect:
    def test_email_detected(self, pii_rule):
        call = ToolCall(name="send_email", args={"body": "Contact alice@example.com"})
        result = eval_pii_detect(pii_rule, call)
        assert result.decision == Decision.BLOCK
        assert "email" in result.reason

    def test_hkid_detected(self, pii_rule):
        call = ToolCall(name="search", args={"query": "HKID A123456(7)"})
        result = eval_pii_detect(pii_rule, call)
        assert result.decision == Decision.BLOCK
        assert "hk_id" in result.reason

    def test_no_pii_passes(self, pii_rule):
        call = ToolCall(name="search", args={"query": "find all active users"})
        result = eval_pii_detect(pii_rule, call)
        assert result.decision == Decision.ALLOW

    def test_nested_args_scanned(self, pii_rule):
        call = ToolCall(
            name="process",
            args={"data": {"nested": {"deep": "email: test@test.com"}}},
        )
        result = eval_pii_detect(pii_rule, call)
        assert result.decision == Decision.BLOCK


class TestEntitlement:
    def test_allowed_role(self, entitlement_rule):
        call = ToolCall(
            name="search",
            args={},
            metadata={"role": "analyst"},
        )
        result = eval_entitlement(entitlement_rule, call)
        assert result.decision == Decision.ALLOW

    def test_blocked_role(self, entitlement_rule):
        call = ToolCall(
            name="execute_sql",
            args={},
            metadata={"role": "analyst"},
        )
        result = eval_entitlement(entitlement_rule, call)
        assert result.decision == Decision.BLOCK

    def test_admin_wildcard(self, entitlement_rule):
        call = ToolCall(
            name="anything",
            args={},
            metadata={"role": "admin"},
        )
        result = eval_entitlement(entitlement_rule, call)
        assert result.decision == Decision.ALLOW

    def test_unknown_user_default_block(self, entitlement_rule):
        call = ToolCall(name="search", args={}, user_id="unknown")
        result = eval_entitlement(entitlement_rule, call)
        assert result.decision == Decision.BLOCK
        assert "No role mapping" in result.reason
