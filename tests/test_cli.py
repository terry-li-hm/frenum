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

    @pytest.mark.skipif(
        not _yaml_available(), reason="pyyaml not installed"
    )
    def test_min_coverage_pass(self, tmp_path):
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
            "--min-coverage", "100",
        ])
        assert result == 0

    @pytest.mark.skipif(
        not _yaml_available(), reason="pyyaml not installed"
    )
    def test_min_coverage_fail(self, tmp_path):
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
            "  - name: block_delete\n"
            "    type: regex_block\n"
            "    applies_to: ['execute_sql']\n"
            "    params:\n"
            "      fields: ['query']\n"
            "      patterns: ['(?i)DELETE\\s+FROM']\n"
        )
        tests = tmp_path / "tests.yaml"
        # Only exercises block_drop, not block_delete → 50% coverage
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
            "--min-coverage", "80",
        ])
        assert result == 1

    def test_init_creates_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = main(["init"])
        assert result == 0
        assert (tmp_path / "policy.yaml").exists()
        assert (tmp_path / "tests.yaml").exists()

    def test_init_skips_existing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "policy.yaml").write_text("existing")
        result = main(["init"])
        assert result == 0
        # policy.yaml untouched
        assert (tmp_path / "policy.yaml").read_text() == "existing"
        # tests.yaml created
        assert (tmp_path / "tests.yaml").exists()
