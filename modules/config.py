from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path("/opt/hecatrace/config/config.yaml")


@dataclass
class PlasoCfg:
    worker_memory_limit: int
    parsers: str
    storage_filename: str
    psort_filename: str


@dataclass
class KeywordsCfg:
    generic_file: Path
    generic_image: Path
    custom_file: list[Path]
    custom_image: list[Path]


@dataclass
class Config:
    evidence_root: Path
    output_root: Path
    logs_root: Path
    resources_dir: Path
    max_parallel_tasks: int
    plaso: PlasoCfg
    keywords: KeywordsCfg
    internal_tools: dict[str, str] = field(default_factory=dict)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    raw: dict[str, Any] = {}
    if path.is_file():
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

    def _env(key: str, fallback: str) -> str:
        return os.environ.get(key, raw.get(fallback, ""))

    evidence_root = Path(_env("HECATRACE_EVIDENCE_ROOT", "evidence_root") or "/evidences")
    output_root   = Path(_env("HECATRACE_OUTPUT_ROOT",   "output_root")   or "/output")
    logs_root     = Path(_env("HECATRACE_LOGS_ROOT",     "logs_root")     or "/logs")
    resources_dir = Path(raw.get("resources_dir", "/opt/hecatrace/resources"))

    kw_raw = raw.get("keywords", {})
    plaso_raw = raw.get("plaso", {})

    def _kw_path(key: str, default: str) -> Path:
        val = kw_raw.get(key, default)
        p = Path(val)
        return p if p.is_absolute() else (resources_dir / val).resolve()

    def _kw_list(key: str) -> list[Path]:
        return [Path(p) for p in kw_raw.get(key, [])]

    return Config(
        evidence_root=evidence_root,
        output_root=output_root,
        logs_root=logs_root,
        resources_dir=resources_dir,
        max_parallel_tasks=int(raw.get("max_parallel_tasks", 6)),
        plaso=PlasoCfg(
            worker_memory_limit=int(plaso_raw.get("worker_memory_limit", 4 * 1024 ** 3)),
            parsers=str(plaso_raw.get("parsers", "win7_slow")),
            storage_filename=str(plaso_raw.get("storage_filename", "evidence.plaso")),
            psort_filename=str(plaso_raw.get("psort_filename", "output.psort")),
        ),
        keywords=KeywordsCfg(
            generic_file=_kw_path("generic_file", "keywords/generic_file.txt"),
            generic_image=_kw_path("generic_image", "keywords/generic_image.txt"),
            custom_file=_kw_list("custom_file"),
            custom_image=_kw_list("custom_image"),
        ),
        internal_tools={
            k: v for k, v in (raw.get("internal_tools") or {}).items() if v
        },
    )
