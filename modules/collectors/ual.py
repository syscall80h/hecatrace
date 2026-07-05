from __future__ import annotations

import logging
from pathlib import Path

from ..context import EvidenceContext
from ..runner import TaskRunner, run_cmd
from ..tools import ToolRegistry
from ..utils import report_empty

log = logging.getLogger("hecatrace.ual")


def collect_ual(ctx: EvidenceContext, tools: ToolRegistry, runner: TaskRunner) -> None:
    """Parses Windows Server UAL (User Access Logging) databases with KStrike."""
    if not ctx.ual_dir.is_dir():
        log.info("[ual] %s missing — not a Windows Server or too old.", ctx.ual_dir)
        return

    log.info("[ual] Parsing UAL MDB databases")
    err_log = ctx.ual_out / "error.log"
    kstrike_cmd = tools.cmd_list("kstrike")

    current = ctx.ual_dir / "Current.mdb"
    if current.is_file():
        out = ctx.ual_out / "ual_current_parsed.psv"
        runner.submit(
            run_cmd,
            kstrike_cmd + [str(current)],
            stdout_file=out,
            stderr_file=err_log,
            append=True,
            label="kstrike:current",
        )

    for mdb in ctx.ual_dir.iterdir():
        if not mdb.is_file() or not mdb.name.endswith(".mdb"):
            continue
        if mdb.name.lower() == "current.mdb":
            continue
        if not mdb.name.endswith("}.mdb"):
            continue
        out = ctx.ual_out / f"ual_{mdb.name}.psv"
        runner.submit(
            run_cmd,
            kstrike_cmd + [str(mdb)],
            stdout_file=out,
            stderr_file=err_log,
            append=True,
            label=f"kstrike:{mdb.name}",
        )

    runner.wait()
    _scrub_nul_bytes(ctx.ual_out)
    report_empty(ctx.ual_out, "ual")


def _scrub_nul_bytes(directory: Path) -> None:
    """Replaces the NUL bytes that KStrike sometimes emits in its outputs."""
    for f in directory.glob("*.psv"):
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if b"\x00" in data:
            f.write_bytes(data.replace(b"\x00", b"-9"))
