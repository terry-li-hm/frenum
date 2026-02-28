"""Tests for the policy linter."""

from frenum._types import RuleConfig
from frenum.lint import lint_policy


class TestE001InvalidRegex:
    def test_invalid_regex_block_pattern(self):
        rules = [
            RuleConfig(
                name="bad_block",
                rule_type="regex_block",
                params={"fields": ["msg"], "patterns": ["[a-z"]},
                applies_to=["*"],
            ),
        ]
        warnings = lint_policy(rules)
        assert any(w.code == "E001" for w in warnings)

    def test_invalid_regex_require_pattern(self):
        rules = [
            RuleConfig(
                name="bad_require",
                rule_type="regex_require",
                params={"fields": ["msg"], "pattern": "*bad"},
                applies_to=["*"],
            ),
        ]
        warnings = lint_policy(rules)
        assert any(w.code == "E001" for w in warnings)


class TestE002UnknownPiiDetector:
    def test_unknown_detector(self):
        rules = [
            RuleConfig(
                name="pii_rule",
                rule_type="pii_detect",
                params={"detectors": ["email", "unknown_detector"]},
                applies_to=["*"],
            ),
        ]
        warnings = lint_policy(rules)
        assert any(
            w.code == "E002" and "unknown_detector" in w.message
            for w in warnings
        )


class TestE003DuplicateNames:
    def test_duplicate_rule_names(self):
        rules = [
            RuleConfig(
                name="dup", rule_type="budget",
                params={"max_cost": 10}, applies_to=["*"],
            ),
            RuleConfig(
                name="dup", rule_type="budget",
                params={"max_cost": 20}, applies_to=["*"],
            ),
        ]
        warnings = lint_policy(rules)
        assert any(w.code == "E003" and "dup" in w.message for w in warnings)


class TestW001EmptyAppliesTo:
    def test_empty_applies_to(self):
        rules = [
            RuleConfig(
                name="empty", rule_type="budget",
                params={"max_cost": 10}, applies_to=[],
            ),
        ]
        warnings = lint_policy(rules)
        assert any(w.code == "W001" for w in warnings)


class TestW002MissingParams:
    def test_missing_required_params(self):
        rules = [
            RuleConfig(
                name="r1", rule_type="regex_block",
                params={"fields": ["f"]}, applies_to=["*"],
            ),
            RuleConfig(
                name="r2", rule_type="regex_require",
                params={"fields": ["f"]}, applies_to=["*"],
            ),
            RuleConfig(
                name="r3", rule_type="pii_detect",
                params={}, applies_to=["*"],
            ),
            RuleConfig(
                name="r4", rule_type="entitlement",
                params={}, applies_to=["*"],
            ),
            RuleConfig(
                name="r5", rule_type="budget",
                params={}, applies_to=["*"],
            ),
            RuleConfig(
                name="r6", rule_type="tool_allowlist",
                params={}, applies_to=["*"],
            ),
        ]
        warnings = lint_policy(rules)
        w002s = [w for w in warnings if w.code == "W002"]
        assert len(w002s) >= 6
        assert any(
            w.rule_name == "r1" and "patterns" in w.message for w in w002s
        )
        assert any(
            w.rule_name == "r2" and "pattern" in w.message for w in w002s
        )
        assert any(
            w.rule_name == "r3" and "detectors" in w.message for w in w002s
        )
        assert any(
            w.rule_name == "r4" and "roles" in w.message for w in w002s
        )
        assert any(
            w.rule_name == "r5" and "max_cost" in w.message for w in w002s
        )
        assert any(
            w.rule_name == "r6" and "allowed_tools" in w.message for w in w002s
        )


class TestW003UnknownRuleType:
    def test_unknown_rule_type(self):
        rules = [
            RuleConfig(
                name="unknown", rule_type="mystery",
                params={}, applies_to=["*"],
            ),
        ]
        warnings = lint_policy(rules)
        assert any(w.code == "W003" for w in warnings)


class TestValidPolicy:
    def test_no_warnings(self):
        rules = [
            RuleConfig(
                name="valid_regex",
                rule_type="regex_block",
                params={"fields": ["msg"], "patterns": [r"^[a-z]+$"]},
                applies_to=["*"],
            ),
            RuleConfig(
                name="valid_pii",
                rule_type="pii_detect",
                params={"detectors": ["email", "phone_intl"]},
                applies_to=["user_info"],
            ),
        ]
        warnings = lint_policy(rules)
        assert len(warnings) == 0
