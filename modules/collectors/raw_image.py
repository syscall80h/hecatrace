from __future__ import annotations

import logging

from ..context import EvidenceContext
from ..runner import run_cmd
from ..tools import ToolRegistry
from ..utils import report_empty

log = logging.getLogger("hecatrace.raw_image")


def collect_raw_image(ctx: EvidenceContext, tools: ToolRegistry) -> None:
    """Computes the fls bodyfile, adds $I30 entries, produces the mactime timeline."""
    if not ctx.raw_mode:
        return
    if ctx.image_path is None:
        log.warning("[raw] No raw image (-i). Step skipped.")
        return
    if ctx.offset is None:
        log.warning("[raw] No partition offset (-o). fls/INDXRipper skipped.")
        return

    log.info("[raw] fls on %s @ offset %d", ctx.image_path, ctx.offset)
    bodyfile = ctx.mft_out / "fls.bodyfile"
    err_log  = ctx.mft_out / "error.log"

    run_cmd(
        tools.cmd_list("fls") + [
            "-r", "-m", "C:", "-p", "-r",
            str(ctx.image_path),
            "-o", str(ctx.offset),
        ],
        stdout_file=bodyfile,
        stderr_file=err_log,
        append=True,
        label="fls",
    )

    log.info("[raw] INDXRipper → adding $I30 entries")
    run_cmd(
        tools.cmd_list("indx_ripper") + [
            "-o", str(ctx.offset),
            "-m", "C:",
            "-w", "bodyfile",
            "--no-active-files",
            str(ctx.image_path),
            str(bodyfile),
        ],
        stderr_file=err_log,
        append=True,
        label="INDXRipper",
    )

    log.info("[raw] mactime timeline")
    run_cmd(
        tools.cmd_list("mactime") + ["-b", str(bodyfile), "-d", "-y"],
        stdout_file=ctx.mft_out / "fls.timeline",
        stderr_file=err_log,
        append=True,
        label="mactime",
    )

    report_empty(ctx.mft_out, "raw")
