from __future__ import annotations

import logging

from ..context import EvidenceContext, HIVES, find_case_insensitive, find_ci_file, find_usrclass, BASE_AMCACHE_PATH, AMCACHE_FNAME
from ..runner import TaskRunner, run_cmd
from ..tools import ToolRegistry
from ..utils import report_empty

log = logging.getLogger("hecatrace.registry")


def collect_registry(ctx: EvidenceContext, tools: ToolRegistry, runner: TaskRunner) -> None:
    """Parses SAM/SOFTWARE/SYSTEM + amcache + NTUSER.DAT / USRCLASS.DAT per user."""
    log.info("[registry] Starting RegRipper")
    err_log = ctx.registry_out / "error.log"
    rip_cmd = tools.cmd_list("regripper")
    rip_cwd = tools.cwd("regripper")

    # System hives
    for hive in HIVES:
        hive_path = ctx.config_dir / hive
        if not hive_path.is_file():
            log.warning("[registry] Missing hive: %s", hive_path)
            continue
        out = ctx.registry_out / f"rip_{hive}.txt"
        runner.submit(
            run_cmd,
            rip_cmd + ["-r", str(hive_path), "-a", "-aT"],
            cwd=rip_cwd,
            stdout_file=out,
            stderr_file=err_log,
            append=True,
            label=f"rip:{hive}",
        )

    # AmCache
    for amcache in find_case_insensitive(ctx.base_path, BASE_AMCACHE_PATH, AMCACHE_FNAME):
        out = ctx.registry_out / "rip_amcache.txt"
        runner.submit(
            run_cmd,
            rip_cmd + ["-r", str(amcache), "-a", "-aT"],
            cwd=rip_cwd,
            stdout_file=out,
            stderr_file=err_log,
            append=True,
            label="rip:amcache",
        )

    # NTUSER.DAT and USRCLASS.DAT per user
    if ctx.user_dir.is_dir():
        for user_dir in ctx.user_dir.iterdir():
            if not user_dir.is_dir():
                continue
            username = user_dir.name

            ntuser = find_ci_file(user_dir, "ntuser.dat")
            if ntuser:
                out = ctx.registry_out / "ntuser" / f"rip_{username}_ntuser.txt"
                err = ctx.registry_out / "ntuser" / "error.log"
                runner.submit(
                    run_cmd,
                    rip_cmd + ["-r", str(ntuser), "-a", "-aT"],
                    cwd=rip_cwd,
                    stdout_file=out,
                    stderr_file=err,
                    append=True,
                    label=f"rip:ntuser:{username}",
                )

            usrclass = find_usrclass(user_dir)
            if usrclass:
                out = ctx.registry_out / "usrclass" / f"rip_{username}_usrclass.txt"
                err = ctx.registry_out / "usrclass" / "error.log"
                runner.submit(
                    run_cmd,
                    rip_cmd + ["-r", str(usrclass), "-a", "-aT"],
                    cwd=rip_cwd,
                    stdout_file=out,
                    stderr_file=err,
                    append=True,
                    label=f"rip:usrclass:{username}",
                )

    runner.wait()
    report_empty(ctx.registry_out, "registry")
