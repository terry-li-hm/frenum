"""CLI entry point: frenum test, frenum lint, frenum init."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_STARTER_POLICY = """\
policy_version: "1.0.0"

rules:
  # Block dangerous SQL patterns
  - name: block_sql_injection
    type: regex_block
    applies_to: ["execute_sql"]
    params:
      fields: ["query"]
      patterns:
        - "(?i)(DROP|DELETE|TRUNCATE)\\\\s+TABLE"

  # Scan all tool calls for PII leakage
  - name: detect_pii
    type: pii_detect
    applies_to: ["*"]
    params:
      detectors: [email, phone_intl, credit_card, ssn]
      action: block

  # Only allow known tools
  - name: allowed_tools_only
    type: tool_allowlist
    applies_to: ["*"]
    params:
      allowed_tools: ["execute_sql", "search", "get_data"]
"""

_STARTER_TESTS = """\
tests:
  - description: SQL injection blocked
    tool_call:
      name: execute_sql
      args:
        query: "DROP TABLE users"
    expected: block
    expected_rule: block_sql_injection

  - description: Clean query allowed
    tool_call:
      name: execute_sql
      args:
        query: "SELECT * FROM users WHERE id = 1"
    expected: allow

  - description: PII in args blocked
    tool_call:
      name: search
      args:
        query: "Contact alice@example.com"
    expected: block
    expected_rule: detect_pii

  - description: Unknown tool blocked
    tool_call:
      name: delete_account
      args:
        user_id: "123"
    expected: block
    expected_rule: allowed_tools_only
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="frenum",
        description="Guardrail lifecycle CLI for LLM agent tool calls",
    )
    sub = parser.add_subparsers(dest="command")

    # frenum test
    test_parser = sub.add_parser(
        "test", help="Run guardrail regression tests against a policy"
    )
    test_parser.add_argument(
        "--config", required=True, help="Path to policy YAML file"
    )
    test_parser.add_argument(
        "--tests", required=True,
        help="Path to test YAML file or directory",
    )
    test_parser.add_argument(
        "--format", choices=["text", "json", "html"], default="text",
        help="Output format",
    )
    test_parser.add_argument(
        "--output", help="Write report to file (default: stdout)"
    )
    test_parser.add_argument(
        "--min-coverage", type=float, default=None, metavar="PCT",
        help="Fail if coverage drops below this percentage (0-100)",
    )

    # frenum lint
    lint_parser = sub.add_parser(
        "lint", help="Static analysis of policy configuration"
    )
    lint_parser.add_argument(
        "--config", required=True, help="Path to policy YAML file"
    )

    # frenum init
    sub.add_parser(
        "init", help="Scaffold a starter policy.yaml and tests.yaml"
    )

    args = parser.parse_args(argv)

    if args.command == "test":
        return _cmd_test(args)
    elif args.command == "lint":
        return _cmd_lint(args)
    elif args.command == "init":
        return _cmd_init()
    else:
        parser.print_help()
        return 2


def _cmd_test(args: argparse.Namespace) -> int:
    from frenum import report
    from frenum.engine import Engine
    from frenum.loader import load_policy, load_tests

    config_path = Path(args.config)
    tests_path = Path(args.tests)

    if not config_path.exists():
        print(f"Error: config file not found: {config_path}", file=sys.stderr)
        return 2
    if not tests_path.exists():
        print(f"Error: tests path not found: {tests_path}", file=sys.stderr)
        return 2

    try:
        rules, policy_version = load_policy(config_path)
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        return 2

    try:
        test_cases = load_tests(tests_path)
    except Exception as e:
        print(f"Error loading tests: {e}", file=sys.stderr)
        return 2

    engine = Engine(rules, policy_version=policy_version)
    policy_content = config_path.read_text()
    results = engine.run_tests(test_cases)
    coverage = engine.calculate_coverage(results)

    if args.format == "json":
        output = report.generate_json(results, coverage, policy_content)
    elif args.format == "html":
        output = report.generate_html(results, coverage, policy_content)
    else:
        output = report.generate_text(results, coverage, policy_content)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    has_failures = any(not r.passed for r in results)
    if has_failures:
        return 1

    if args.min_coverage is not None and coverage.coverage_pct < args.min_coverage:
        print(
            f"Coverage {coverage.coverage_pct:.1f}% below threshold {args.min_coverage:.1f}%",
            file=sys.stderr,
        )
        return 1

    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    from frenum.lint import lint_policy
    from frenum.loader import load_policy

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: config file not found: {config_path}", file=sys.stderr)
        return 2

    try:
        rules, _ = load_policy(config_path)
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        return 2

    warnings = lint_policy(rules)

    if not warnings:
        print("No issues found.")
        return 0

    errors = [w for w in warnings if w.severity == "error"]
    warns = [w for w in warnings if w.severity == "warning"]

    for w in warnings:
        prefix = "ERROR" if w.severity == "error" else "WARN"
        rule_ctx = f" [{w.rule_name}]" if w.rule_name else ""
        print(f"  {prefix} {w.code}{rule_ctx}: {w.message}")

    print(f"\n{len(errors)} error(s), {len(warns)} warning(s)")
    return 1 if errors else 0


def _cmd_init() -> int:
    policy_path = Path("policy.yaml")
    tests_path = Path("tests.yaml")

    wrote = []
    for path, content in [(policy_path, _STARTER_POLICY), (tests_path, _STARTER_TESTS)]:
        if path.exists():
            print(f"  skip  {path} (already exists)", file=sys.stderr)
        else:
            path.write_text(content)
            wrote.append(path)
            print(f"  wrote {path}")

    if wrote:
        print("\nRun: frenum lint --config policy.yaml")
        print("     frenum test --config policy.yaml --tests tests.yaml")
    else:
        print("\nNothing to write — both files already exist.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
