"""Tests for the CLI."""

import pytest

from frenum.cli import main


def _yaml_available() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except ImportError:
        return False


class TestCli:
    def test_no_command_returns_2(self):
        assert main([]) == 2

    def test_test_missing_config(self, tmp_path):
        result = main([
            "test",
            "--config", str(tmp_path / "nope.yaml"),
            "--tests", str(tmp_path),
        ])
        assert result == 2

    def test_lint_missing_config(self, tmp_path):
        result = main([
            "lint",
            "--config", str(tmp_path / "nope.yaml"),
        ])
        assert result == 2

    @pytest.mark.skipif(
        not _yaml_available(), reason="pyyaml not installed"
    )
    def test_test_integration(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "policy_version: '1.0.0'\n"
            "rules:\n"
            "  - name: block_drop\n"
            "    type: regex_block\n"
            "    applies_to: ['execute_sql']\n"
            "    params:\n"
            "      fields: ['query']\n"
            "      patterns: ['(?i)DROP\\s+TABLE']\n"
        )
        tests = tmp_path / "tests.yaml"
        tests.write_text(
            "tests:\n"
            "  - description: SQL injection blocked\n"
            "    tool_call:\n"
            "      name: execute_sql\n"
            "      args:\n"
            "        query: DROP TABLE users\n"
            "    expected: block\n"
        )
        result = main([
            "test",
            "--config", str(policy),
            "--tests", str(tests),
        ])
        assert result == 0

    @pytest.mark.skipif(
        not _yaml_available(), reason="pyyaml not installed"
    )
    def test_lint_integration(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "policy_version: '1.0.0'\n"
            "rules:\n"
            "  - name: valid_rule\n"
            "    type: regex_block\n"
            "    applies_to: ['*']\n"
            "    params:\n"
            "      fields: ['q']\n"
            "      patterns: ['^ok$']\n"
        )
        result = main(["lint", "--config", str(policy)])
        assert result == 0
