"""Tests for test report generators."""

import json

from frenum._types import (
    CoverageReport,
    Decision,
    TestCaseConfig,
    TestResult,
    ToolCall,
)
from frenum.report import generate_html, generate_json, generate_text


def _make_result(passed=True, description="test", actual_rule=None):
    expected = Decision.BLOCK if actual_rule else Decision.ALLOW
    actual = expected if passed else (
        Decision.ALLOW if expected == Decision.BLOCK else Decision.BLOCK
    )
    return TestResult(
        test_case=TestCaseConfig(
            description=description,
            tool_call=ToolCall(name="tool", args={}),
            expected=expected,
        ),
        actual=actual,
        actual_rule=actual_rule,
        passed=passed,
        reason="ok" if passed else "failed",
        rules_evaluated=["rule1"],
    )


def _coverage():
    return CoverageReport(
        total_deterministic_rules=3,
        rules_exercised=["rule1", "rule2"],
        rules_not_exercised=["rule3"],
        semantic_rules=["sem1"],
        coverage_pct=66.7,
    )


class TestTextReport:
    def test_basic_text(self):
        results = [_make_result(), _make_result(passed=False)]
        text = generate_text(results, _coverage(), "policy content")
        assert "frenum" in text
        assert "1/2 passed" in text
        assert "66.7%" in text
        assert "rule3" in text
        assert "sem1" in text

    def test_evidence_hash_present(self):
        text = generate_text([_make_result()], _coverage(), "policy")
        assert "Evidence hash:" in text


class TestJsonReport:
    def test_parseable_json(self):
        output = generate_json([_make_result()], _coverage(), "policy")
        data = json.loads(output)
        assert data["summary"]["total"] == 1
        assert data["summary"]["passed"] == 1
        assert data["coverage"]["coverage_pct"] == 66.7
        assert "evidence_hash" in data
        assert len(data["evidence_hash"]) == 64


class TestHtmlReport:
    def test_html_output(self):
        output = generate_html([_make_result()], _coverage())
        assert "<html" in output
        assert "frenum" in output
        assert "66.7%" in output
