from __future__ import annotations

import logging

from ..context import EvidenceContext
from ..runner import TaskRunner, run_cmd
from ..tools import ToolRegistry
from ..utils import report_empty

log = logging.getLogger("hecatrace.mft")


def collect_mft(ctx: EvidenceContext, tools: ToolRegistry, runner: TaskRunner) -> None:
    """Parses the $MFT file(s) with analyzeMFT."""
    log.info("[mft] Starting MFT parsing")
    err_log = ctx.mft_out / "error.log"
    amft_cmd = tools.cmd_list("analyze_mft")

    if ctx.raw_mode:
        mft_file = ctx.mft_path / "$MFT"
        if mft_file.is_file():
            out = ctx.mft_out / "MFT_parsed.csv"
            runner.submit(
                run_cmd,
                amft_cmd + ["--bodyfull", "-f", str(mft_file), "-c", str(out)],
                stderr_file=err_log,
                append=True,
                label="analyzeMFT:root",
            )
        else:
            log.warning("[mft] No $MFT found at %s", mft_file)
    else:
        if not ctx.mft_path.is_dir():
            log.warning("[mft] MFT directory missing: %s", ctx.mft_path)
        else:
            for entry in sorted(ctx.mft_path.iterdir()):
                if not entry.is_dir():
                    continue
                mft_file = entry / "$MFT"
                if not mft_file.is_file():
                    continue
                safe_name = entry.name.replace("$", "").replace("/", "")
                out = ctx.mft_out / f"{safe_name}_parsed.csv"
                runner.submit(
                    run_cmd,
                    amft_cmd + ["--bodyfull", "-f", str(mft_file), "-c", str(out)],
                    stderr_file=err_log,
                    append=True,
                    label=f"analyzeMFT:{entry.name}",
                )

    runner.wait()
    report_empty(ctx.mft_out, "mft")
