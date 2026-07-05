from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hecatrace.report")


@dataclass
class CollectorResult:
    name: str
    status: str           # "ok" | "warn" | "error" | "skipped"
    duration_s: float = 0.0
    details: dict = field(default_factory=dict)


class Report:
    """Accumulates pipeline results and generates a JSON report."""

    def __init__(self, evidence_root: str, output_path: str):
        self.started_at = datetime.now(timezone.utc)
        self.evidence_root = evidence_root
        self.output_path = output_path
        self.collectors: list[CollectorResult] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.missing_optional: list[str] = []

    def add_collector(self, result: CollectorResult) -> None:
        self.collectors.append(result)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def write(self, path: Path) -> None:
        finished_at = datetime.now(timezone.utc)
        data = {
            "hecatrace_version": "1.0.0",
            "started_at": self.started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_s": round((finished_at - self.started_at).total_seconds(), 2),
            "evidence_root": self.evidence_root,
            "output_path": self.output_path,
            "collectors": [
                {"name": r.name, "status": r.status, "duration_s": round(r.duration_s, 2), **r.details}
                for r in self.collectors
            ],
            "missing_optional_tools": self.missing_optional,
            "warnings": self.warnings,
            "errors": self.errors,
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Report written: %s", path)
