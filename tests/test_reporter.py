"""Tests for the audit reporter."""

import json
from datetime import datetime, timezone

from obex import AuditReporter


def _write_records(path, records):
    with path.open("w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


class TestAuditReporter:
    def test_basic_report(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        _write_records(
            log_path,
            [
                {
                    "decision_id": "abc123",
                    "timestamp": "2026-02-28T10:00:00+00:00",
                    "policy_version": "1.0.0",
                    "decision": "allow",
                    "tool_name": "search",
                    "blocking_rule": None,
                },
                {
                    "decision_id": "def456",
                    "timestamp": "2026-02-28T10:05:00+00:00",
                    "policy_version": "1.0.0",
                    "decision": "block",
                    "tool_name": "execute_sql",
                    "blocking_rule": "block_sql_injection",
                },
                {
                    "decision_id": "ghi789",
                    "timestamp": "2026-02-28T10:10:00+00:00",
                    "policy_version": "1.0.0",
                    "decision": "allow",
                    "tool_name": "search",
                    "blocking_rule": None,
                },
            ],
        )

        reporter = AuditReporter(log_path)
        report = reporter.generate()

        assert report.total_evaluations == 3
        assert report.decisions["allow"] == 2
        assert report.decisions["block"] == 1
        assert report.total_blocks == 1
        assert report.by_rule["block_sql_injection"] == 1
        assert ("execute_sql", 1) in report.top_blocked_tools

    def test_date_filtering(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        _write_records(
            log_path,
            [
                {
                    "decision_id": "a",
                    "timestamp": "2026-02-27T10:00:00+00:00",
                    "decision": "allow",
                    "tool_name": "search",
                },
                {
                    "decision_id": "b",
                    "timestamp": "2026-02-28T10:00:00+00:00",
                    "decision": "block",
                    "tool_name": "sql",
                    "blocking_rule": "r1",
                },
            ],
        )

        reporter = AuditReporter(log_path)
        report = reporter.generate(
            start=datetime(2026, 2, 28, tzinfo=timezone.utc),
        )

        assert report.total_evaluations == 1
        assert report.decisions.get("block") == 1

    def test_override_rate(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        _write_records(
            log_path,
            [
                {
                    "decision_id": "a",
                    "timestamp": "2026-02-28T10:00:00+00:00",
                    "decision": "block",
                    "tool_name": "sql",
                    "blocking_rule": "r1",
                    "human_override": {"overridden_by": "admin", "reason": "approved"},
                },
                {
                    "decision_id": "b",
                    "timestamp": "2026-02-28T10:05:00+00:00",
                    "decision": "block",
                    "tool_name": "sql",
                    "blocking_rule": "r1",
                    "human_override": None,
                },
            ],
        )

        reporter = AuditReporter(log_path)
        report = reporter.generate()

        assert report.total_blocks == 2
        assert report.override_count == 1
        assert report.override_rate == 0.5

    def test_empty_log(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_path.touch()

        reporter = AuditReporter(log_path)
        report = reporter.generate()

        assert report.total_evaluations == 0

    def test_nonexistent_file(self, tmp_path):
        log_path = tmp_path / "missing.jsonl"
        reporter = AuditReporter(log_path)
        report = reporter.generate()
        assert report.total_evaluations == 0

    def test_to_text_output(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        _write_records(
            log_path,
            [
                {
                    "decision_id": "a",
                    "timestamp": "2026-02-28T10:00:00+00:00",
                    "policy_version": "1.0.0",
                    "decision": "allow",
                    "tool_name": "search",
                },
            ],
        )

        reporter = AuditReporter(log_path)
        report = reporter.generate()
        text = report.to_text()

        assert "OBEX AUDIT REPORT" in text
        assert "Total evaluations: 1" in text

    def test_to_dict_output(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        _write_records(
            log_path,
            [
                {
                    "decision_id": "a",
                    "timestamp": "2026-02-28T10:00:00+00:00",
                    "decision": "allow",
                    "tool_name": "search",
                },
            ],
        )

        reporter = AuditReporter(log_path)
        report = reporter.generate()
        d = report.to_dict()

        assert d["total_evaluations"] == 1
        assert "period_start" in d
