from __future__ import annotations

import logging

from ..context import EvidenceContext, TRIAGE_VELOCIRAPTOR
from ..runner import TaskRunner, run_cmd
from ..tools import ToolRegistry
from ..utils import report_empty

log = logging.getLogger("hecatrace.usn")


def collect_usn(ctx: EvidenceContext, tools: ToolRegistry, runner: TaskRunner) -> None:
    """Parses $UsnJrnl:$J on each volume found."""
    log.info("[usn] Parsing USN journals")
    err_log = ctx.usn_out / "error.log"
    usn_cmd = tools.cmd_list("usn_parser")

    # Velociraptor URL-encodes the name
    usn_leaf = "$UsnJrnl%3A$J" if ctx.triage_type == TRIAGE_VELOCIRAPTOR else "$UsnJrnl"

    if not ctx.mft_path.is_dir():
        log.warning("[usn] MFT path missing: %s", ctx.mft_path)
        return

    found = 0
    for volume in sorted(ctx.mft_path.iterdir()):
        if not volume.is_dir():
            continue
        usn_file = volume / "$Extend" / usn_leaf
        if not usn_file.is_file():
            continue
        found += 1
        safe_name = (
            volume.name
            .replace("$", "")
            .replace("/", "")
            .replace("%5C%5C.%5C", "")
            .replace("%3A", "_")
        )
        out = ctx.usn_out / f"{safe_name}_parsed.csv"
        runner.submit(
            run_cmd,
            usn_cmd + ["-f", str(usn_file), "-c", "-o", str(out)],
            stderr_file=err_log,
            append=True,
            label=f"usn:{volume.name}",
        )

    # Raw image: $UsnJrnl at the root of the mount point
    if ctx.raw_mode and found == 0:
        usn_file = ctx.mft_path / "$Extend" / usn_leaf
        if usn_file.is_file():
            out = ctx.usn_out / "usn_parsed.csv"
            runner.submit(
                run_cmd,
                usn_cmd + ["-f", str(usn_file), "-c", "-o", str(out)],
                stderr_file=err_log,
                append=True,
                label="usn:root",
            )
            found += 1

    runner.wait()
    if found == 0:
        log.warning("[usn] No USN journal found.")
    report_empty(ctx.usn_out, "usn")
