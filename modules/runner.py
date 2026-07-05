from __future__ import annotations

import logging
import shlex
import subprocess
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("hecatrace.runner")


@dataclass
class CmdResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    label: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_cmd(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    stdout_file: Optional[Path] = None,
    stderr_file: Optional[Path] = None,
    append: bool = False,
    label: str = "",
    env: Optional[dict[str, str]] = None,
    check: bool = False,
    timeout: Optional[float] = None,
) -> CmdResult:
    """Run an external command without shell=True; optionally redirect output to files."""
    start = time.monotonic()
    label = label or " ".join(shlex.quote(c) for c in cmd[:3])
    log.debug("RUN [%s]: %s", label, " ".join(shlex.quote(c) for c in cmd))

    mode = "ab" if append else "wb"
    stdout_fh = open(stdout_file, mode) if stdout_file else subprocess.PIPE
    stderr_fh = open(stderr_file, mode) if stderr_file else subprocess.PIPE

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=stdout_fh,
            stderr=stderr_fh,
            env=env,
            check=False,
            timeout=timeout,
        )
        stdout_str = proc.stdout.decode("utf-8", errors="replace") if proc.stdout is not None else ""
        stderr_str = proc.stderr.decode("utf-8", errors="replace") if proc.stderr is not None else ""
    finally:
        if stdout_file and hasattr(stdout_fh, "close"):
            stdout_fh.close()
        if stderr_file and hasattr(stderr_fh, "close"):
            stderr_fh.close()

    duration = time.monotonic() - start
    result = CmdResult(
        cmd=cmd,
        returncode=proc.returncode,
        stdout=stdout_str,
        stderr=stderr_str,
        duration_s=duration,
        label=label,
    )

    if result.ok:
        log.debug("OK  [%s] in %.1fs", label, duration)
    else:
        log.warning(
            "FAIL [%s] rc=%d in %.1fs: %s",
            label, result.returncode, duration,
            (result.stderr or "")[:500],
        )
        if check:
            raise RuntimeError(f"Command failed ({label}): rc={result.returncode}")
    return result


class TaskRunner:
    """Bounded-parallelism executor for subprocess tasks."""

    def __init__(self, max_workers: int):
        self.max_workers = max(1, max_workers)
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self._futures: list[Future] = []

    def submit(self, fn: Callable[..., CmdResult], *args, **kwargs) -> Future:
        fut = self._executor.submit(fn, *args, **kwargs)
        self._futures.append(fut)
        return fut

    def wait(self) -> list[CmdResult]:
        results: list[CmdResult] = []
        for fut in as_completed(self._futures):
            try:
                res = fut.result()
                if isinstance(res, CmdResult):
                    results.append(res)
            except Exception as exc:
                log.exception("Task raised an exception: %s", exc)
        self._futures.clear()
        return results

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True)
