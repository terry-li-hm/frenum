"""Shared fixtures for obex tests."""

import pytest

from obex._types import RuleConfig, RuleType, ToolCall


@pytest.fixture
def simple_tool_call():
    return ToolCall(name="execute_sql", args={"query": "SELECT * FROM users WHERE id = 1"})


@pytest.fixture
def dangerous_tool_call():
    return ToolCall(name="execute_sql", args={"query": "DROP TABLE users"})


@pytest.fixture
def pii_tool_call():
    return ToolCall(
        name="send_email",
        args={"to": "alice@example.com", "body": "Your HKID is A123456(7)"},
    )


@pytest.fixture
def regex_block_rule():
    return RuleConfig(
        name="block_sql_injection",
        rule_type=RuleType.REGEX_BLOCK,
        params={
            "fields": ["query"],
            "patterns": [r"(?i)(DROP|DELETE|TRUNCATE)\s+TABLE"],
        },
        applies_to=["execute_sql"],
    )


@pytest.fixture
def pii_rule():
    return RuleConfig(
        name="detect_pii",
        rule_type=RuleType.PII_DETECT,
        params={"detectors": ["email", "hk_id"], "action": "block"},
        applies_to=["*"],
    )


@pytest.fixture
def entitlement_rule():
    return RuleConfig(
        name="tool_entitlement",
        rule_type=RuleType.ENTITLEMENT,
        params={
            "roles": {
                "analyst": ["search", "get_data"],
                "admin": ["*"],
            },
            "default": "block",
        },
        applies_to=["*"],
    )


@pytest.fixture
def sample_config():
    return {
        "version": "1.0",
        "policy_version": "1.0.0",
        "rules": [
            {
                "name": "block_sql_injection",
                "type": "regex_block",
                "applies_to": ["execute_sql"],
                "params": {
                    "fields": ["query"],
                    "patterns": [r"(?i)(DROP|DELETE|TRUNCATE)\s+TABLE"],
                },
            },
            {
                "name": "detect_pii",
                "type": "pii_detect",
                "applies_to": ["*"],
                "params": {"detectors": ["email", "hk_id"], "action": "block"},
            },
        ],
    }
