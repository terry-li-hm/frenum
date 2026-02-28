"""Audit report generator for obex."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class Report:
    """Summary report from audit logs."""

    period_start: datetime
    period_end: datetime
    total_evaluations: int
    decisions: dict[str, int]  # {"allow": 450, "block": 50}
    by_tool: dict[str, dict[str, int]]  # {"execute_sql": {"allow": 10, "block": 5}}
    by_rule: dict[str, int]  # {"block_sql_injection": 15}
    top_blocked_tools: list[tuple[str, int]] = field(default_factory=list)
    top_triggered_rules: list[tuple[str, int]] = field(default_factory=list)
    override_count: int = 0
    total_blocks: int = 0
    policy_versions_seen: list[str] = field(default_factory=list)

    @property
    def override_rate(self) -> float:
        if self.total_blocks == 0:
            return 0.0
        return self.override_count / self.total_blocks

    def to_text(self) -> str:
        """Human-readable summary report."""
        lines = [
            "=" * 40,
            "OBEX AUDIT REPORT",
            "=" * 40,
            f"Period: {self.period_start:%Y-%m-%d %H:%M} to {self.period_end:%Y-%m-%d %H:%M}",
            f"Policy versions: {', '.join(self.policy_versions_seen) or 'N/A'}",
            "",
            f"Total evaluations: {self.total_evaluations}",
        ]

        for decision, count in sorted(self.decisions.items()):
            pct = (count / self.total_evaluations * 100) if self.total_evaluations else 0
            lines.append(f"  {decision.capitalize():>10}: {count:>6} ({pct:.1f}%)")

        if self.top_blocked_tools:
            lines.append("")
            lines.append("Top blocked tools:")
            for i, (tool, count) in enumerate(self.top_blocked_tools[:5], 1):
                lines.append(f"  {i}. {tool:<30} — {count} blocks")

        if self.top_triggered_rules:
            lines.append("")
            lines.append("Top triggered rules:")
            for i, (rule, count) in enumerate(self.top_triggered_rules[:5], 1):
                lines.append(f"  {i}. {rule:<30} — {count} triggers")

        if self.total_blocks > 0:
            lines.append("")
            lines.append(
                f"Human override rate: {self.override_rate:.1%} "
                f"({self.override_count} of {self.total_blocks} blocks overridden)"
            )

        lines.append("=" * 40)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Machine-readable dict."""
        return {
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "total_evaluations": self.total_evaluations,
            "decisions": self.decisions,
            "by_tool": self.by_tool,
            "by_rule": self.by_rule,
            "top_blocked_tools": self.top_blocked_tools,
            "top_triggered_rules": self.top_triggered_rules,
            "override_rate": self.override_rate,
            "policy_versions_seen": self.policy_versions_seen,
        }


class AuditReporter:
    """Generate summary reports from JSONL audit logs."""

    def __init__(self, path: str | Path):
        self._path = Path(path)

    def generate(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> Report:
        """Parse logs and produce a Report."""
        records = self._load_records(start, end)

        if not records:
            now = datetime.now()
            return Report(
                period_start=start or now,
                period_end=end or now,
                total_evaluations=0,
                decisions={},
                by_tool={},
                by_rule={},
            )

        decision_counts: Counter[str] = Counter()
        tool_decisions: dict[str, Counter[str]] = {}
        rule_triggers: Counter[str] = Counter()
        tool_blocks: Counter[str] = Counter()
        override_count = 0
        total_blocks = 0
        policy_versions: set[str] = set()
        timestamps: list[datetime] = []

        for rec in records:
            decision = rec.get("decision", "allow")
            tool_name = rec.get("tool_name", "unknown")
            blocking_rule = rec.get("blocking_rule")
            policy_ver = rec.get("policy_version", "unknown")

            decision_counts[decision] += 1
            policy_versions.add(policy_ver)

            ts_str = rec.get("timestamp", "")
            if ts_str:
                try:
                    timestamps.append(datetime.fromisoformat(ts_str))
                except ValueError:
                    pass

            if tool_name not in tool_decisions:
                tool_decisions[tool_name] = Counter()
            tool_decisions[tool_name][decision] += 1

            if decision == "block":
                total_blocks += 1
                tool_blocks[tool_name] += 1
                if blocking_rule:
                    rule_triggers[blocking_rule] += 1

            if rec.get("human_override") is not None:
                override_count += 1

        period_start = start or (min(timestamps) if timestamps else datetime.now())
        period_end = end or (max(timestamps) if timestamps else datetime.now())

        return Report(
            period_start=period_start,
            period_end=period_end,
            total_evaluations=len(records),
            decisions=dict(decision_counts),
            by_tool={t: dict(c) for t, c in tool_decisions.items()},
            by_rule=dict(rule_triggers),
            top_blocked_tools=tool_blocks.most_common(10),
            top_triggered_rules=rule_triggers.most_common(10),
            override_count=override_count,
            total_blocks=total_blocks,
            policy_versions_seen=sorted(policy_versions),
        )

    def _load_records(
        self,
        start: datetime | None,
        end: datetime | None,
    ) -> list[dict[str, Any]]:
        """Load and filter JSONL records."""
        if not self._path.exists():
            return []

        records: list[dict[str, Any]] = []
        with self._path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if start or end:
                    ts_str = rec.get("timestamp", "")
                    if ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            if start and ts < start:
                                continue
                            if end and ts > end:
                                continue
                        except ValueError:
                            continue

                records.append(rec)

        return records
