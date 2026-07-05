from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

log = logging.getLogger("hecatrace")


def report_empty(output_dir: Path, label: str, ignore: Iterable[str] = ("error.log",)) -> None:
    """Warns if empty files exist in output_dir (non-recursive)."""
    ignore_set = set(ignore)
    try:
        empties = [
            p for p in output_dir.iterdir()
            if p.is_file() and p.stat().st_size == 0 and p.name not in ignore_set
        ]
    except OSError:
        return
    if empties:
        log.warning("[%s] Empty outputs (check upstream errors):", label)
        for p in empties:
            log.warning("    - %s", p)
    else:
        log.info("[%s] No empty output.", label)


def delete_empty_files(directory: Path, ignore: Iterable[str] = ()) -> None:
    """Deletes empty files in directory (non-recursive)."""
    keep = set(ignore)
    try:
        for p in directory.iterdir():
            if p.is_file() and p.stat().st_size == 0 and p.name not in keep:
                p.unlink()
    except OSError:
        pass


def iter_files(root: Path) -> Iterable[Path]:
    """Recursively iterates over all files under root, ignoring errors."""
    if not root.is_dir():
        return
    for p in root.rglob("*"):
        try:
            if p.is_file():
                yield p
        except OSError:
            continue
