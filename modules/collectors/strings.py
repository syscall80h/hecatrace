from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from ..context import EvidenceContext
from ..tools import ToolRegistry
from ..utils import iter_files, report_empty

log = logging.getLogger("hecatrace.strings")


def collect_strings(ctx: EvidenceContext, tools: ToolRegistry) -> None:
    """Extracts ASCII and UTF-16LE strings, each line prefixed with the source path."""
    log.info("[strings] Extracting strings")
    out = ctx.strings_out / "everything.strings"
    strings_bin = tools.command("strings")

    if ctx.raw_mode:
        targets = [
            p for p in iter_files(ctx.base_path)
            if re.search(r"(pagefile|hiberfile)", p.name, re.IGNORECASE)
        ]
    else:
        targets = list(iter_files(ctx.base_path))

    if not targets:
        log.warning("[strings] No candidate file under %s", ctx.base_path)
        out.touch()
        return

    with open(out, "w", encoding="utf-8", errors="replace") as fh:
        for path in targets:
            for args in (
                [strings_bin, "-td", "-el", "-n", "10", str(path)],
                [strings_bin, "-td", "-n",  "10", str(path)],
            ):
                try:
                    proc = subprocess.run(args, capture_output=True, check=False)
                except (OSError, FileNotFoundError) as exc:
                    log.debug("[strings] Skipped %s: %s", path, exc)
                    continue
                prefix = f"{path}: "
                for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
                    fh.write(prefix)
                    fh.write(line)
                    fh.write("\n")

    report_empty(ctx.strings_out, "strings")
