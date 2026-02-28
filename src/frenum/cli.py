"""CLI entry point: frenum test, frenum lint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


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

    # frenum lint
    lint_parser = sub.add_parser(
        "lint", help="Static analysis of policy configuration"
    )
    lint_parser.add_argument(
        "--config", required=True, help="Path to policy YAML file"
    )

    args = parser.parse_args(argv)

    if args.command == "test":
        return _cmd_test(args)
    elif args.command == "lint":
        return _cmd_lint(args)
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
    return 1 if has_failures else 0


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


if __name__ == "__main__":
    sys.exit(main())
