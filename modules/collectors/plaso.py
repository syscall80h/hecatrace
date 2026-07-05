from __future__ import annotations

import logging

from ..context import EvidenceContext
from ..config import Config
from ..runner import run_cmd
from ..tools import ToolRegistry

log = logging.getLogger("hecatrace.plaso")


def collect_plaso(
    ctx: EvidenceContext,
    cfg: Config,
    tools: ToolRegistry,
    *,
    skip: bool = False,
    overwrite: bool = False,
) -> None:
    """Runs log2timeline then psort. No user interaction."""
    if skip:
        log.info("[plaso] Skipped (--skip-plaso).")
        return

    log2timeline_cmd = tools.cmd_list("log2timeline")
    psort_cmd = tools.cmd_list("psort")

    if ctx.plaso_file.is_file() and not overwrite:
        log.info("[plaso] %s already present — skipped (use --overwrite to rerun).", ctx.plaso_file)
    else:
        log.info("[plaso] Starting log2timeline (can take several hours)")
        stdout_log = ctx.plaso_out / "log2timeline.stdout"

        cmd = log2timeline_cmd + [
            "--storage-file", str(ctx.plaso_file),
            "--worker-memory-limit", str(cfg.plaso.worker_memory_limit),
            "--parsers", cfg.plaso.parsers,
            "--status-view", "file",
            "--status-view-file", str(ctx.plaso_out / "log2timeline.status"),
        ]
        if ctx.raw_mode and ctx.image_path is not None:
            cmd += ["-u", "--partitions", "all", str(ctx.image_path)]
        elif ctx.raw_mode:
            log.warning("[plaso] Raw mode without image — aborting.")
            return
        else:
            cmd += [str(ctx.base_path)]

        run_cmd(cmd, stdout_file=stdout_log, stderr_file=stdout_log, append=True, label="log2timeline")

    if not ctx.plaso_file.is_file():
        log.error("[plaso] %s missing — psort impossible.", ctx.plaso_file)
        return

    log.info("[plaso] Starting psort")
    stdout_log = ctx.plaso_out / "psort.stdout"
    run_cmd(
        psort_cmd + [
            "--worker-memory-limit", str(cfg.plaso.worker_memory_limit),
            "--status-view", "file",
            "--status-view-file", str(ctx.plaso_out / "psort.status"),
            "-w", str(ctx.psort_file),
            "-o", "dynamic",
            str(ctx.plaso_file),
        ],
        stdout_file=stdout_log,
        stderr_file=stdout_log,
        append=True,
        label="psort",
    )
