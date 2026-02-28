"""Tests for Engine.run_tests and Engine.calculate_coverage."""

from frenum import Decision, Engine, RuleConfig, RuleKind, TestCaseConfig, ToolCall


def _engine():
    return Engine(rules=[
        RuleConfig(
            name="block_sql",
            rule_type="regex_block",
            params={"fields": ["query"], "patterns": [r"(?i)DROP\s+TABLE"]},
            applies_to=["execute_sql"],
        ),
        RuleConfig(
            name="detect_pii",
            rule_type="pii_detect",
            params={"detectors": ["email"], "action": "block"},
            applies_to=["*"],
        ),
    ])


class TestRunTests:
    def test_passing_tests(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="SQL injection blocked",
                tool_call=ToolCall(name="execute_sql", args={"query": "DROP TABLE users"}),
                expected=Decision.BLOCK,
            ),
            TestCaseConfig(
                description="Clean query allowed",
                tool_call=ToolCall(name="execute_sql", args={"query": "SELECT 1"}),
                expected=Decision.ALLOW,
            ),
        ]
        results = engine.run_tests(cases)
        assert len(results) == 2
        assert all(r.passed for r in results)

    def test_failing_test(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="Expect allow but gets block",
                tool_call=ToolCall(name="execute_sql", args={"query": "DROP TABLE users"}),
                expected=Decision.ALLOW,
            ),
        ]
        results = engine.run_tests(cases)
        assert len(results) == 1
        assert not results[0].passed

    def test_expected_rule_check(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="Blocked by SQL rule",
                tool_call=ToolCall(name="execute_sql", args={"query": "DROP TABLE users"}),
                expected=Decision.BLOCK,
                expected_rule="block_sql",
            ),
        ]
        results = engine.run_tests(cases)
        assert results[0].passed
        assert results[0].actual_rule == "block_sql"

    def test_wrong_expected_rule_fails(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="Blocked by SQL rule but expects PII",
                tool_call=ToolCall(name="execute_sql", args={"query": "DROP TABLE users"}),
                expected=Decision.BLOCK,
                expected_rule="detect_pii",
            ),
        ]
        results = engine.run_tests(cases)
        assert not results[0].passed
        assert "Expected rule" in results[0].reason

    def test_rules_evaluated_tracked(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="Clean query hits both rules",
                tool_call=ToolCall(name="execute_sql", args={"query": "SELECT 1"}),
                expected=Decision.ALLOW,
            ),
        ]
        results = engine.run_tests(cases)
        assert "block_sql" in results[0].rules_evaluated
        assert "detect_pii" in results[0].rules_evaluated


class TestCoverage:
    def test_full_coverage(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="Hits SQL rule",
                tool_call=ToolCall(name="execute_sql", args={"query": "DROP TABLE x"}),
                expected=Decision.BLOCK,
            ),
            TestCaseConfig(
                description="Hits PII rule",
                tool_call=ToolCall(name="other", args={"data": "test@test.com"}),
                expected=Decision.BLOCK,
            ),
        ]
        results = engine.run_tests(cases)
        coverage = engine.calculate_coverage(results)
        assert coverage.coverage_pct == 100.0
        assert coverage.total_deterministic_rules == 2
        assert len(coverage.rules_not_exercised) == 0

    def test_partial_coverage(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="Only hits SQL",
                tool_call=ToolCall(name="execute_sql", args={"query": "DROP TABLE x"}),
                expected=Decision.BLOCK,
            ),
        ]
        results = engine.run_tests(cases)
        coverage = engine.calculate_coverage(results)
        assert coverage.coverage_pct == 50.0
        assert "detect_pii" in coverage.rules_not_exercised

    def test_semantic_rules_excluded(self):
        engine = Engine(rules=[
            RuleConfig(
                name="det_rule",
                rule_type="regex_block",
                params={"fields": ["q"], "patterns": ["bad"]},
                applies_to=["*"],
            ),
            RuleConfig(
                name="sem_rule",
                rule_type="regex_block",
                params={"fields": ["q"], "patterns": ["x"]},
                applies_to=["*"],
                kind=RuleKind.SEMANTIC,
            ),
        ])
        cases = [
            TestCaseConfig(
                description="Hits det rule",
                tool_call=ToolCall(name="t", args={"q": "bad"}),
                expected=Decision.BLOCK,
            ),
        ]
        results = engine.run_tests(cases)
        coverage = engine.calculate_coverage(results)
        assert coverage.total_deterministic_rules == 1
        assert coverage.coverage_pct == 100.0
        assert "sem_rule" in coverage.semantic_rules

    def test_empty_rules_full_coverage(self):
        engine = Engine()
        coverage = engine.calculate_coverage([])
        assert coverage.coverage_pct == 100.0

    def test_allow_result_counts_as_exercised(self):
        engine = _engine()
        cases = [
            TestCaseConfig(
                description="Clean query exercises both rules via allow path",
                tool_call=ToolCall(name="execute_sql", args={"query": "SELECT 1"}),
                expected=Decision.ALLOW,
            ),
        ]
        results = engine.run_tests(cases)
        coverage = engine.calculate_coverage(results)
        assert coverage.coverage_pct == 100.0
