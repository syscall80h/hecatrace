from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from ..config import Config, KeywordsCfg
from ..context import EvidenceContext
from ..runner import TaskRunner, run_cmd
from ..tools import ToolRegistry

log = logging.getLogger("hecatrace.easy_win")


def run_easy_win(
    ctx: EvidenceContext,
    tools: ToolRegistry,
    cfg: Config,
    runner: TaskRunner,
) -> None:
    """Easy-win orchestration: sysinfo, keywords, Hayabusa, Chainsaw."""
    log.info("[easy] Starting easy-win detection")

    extract_sysinfo(ctx)

    kw = cfg.keywords
    mft_csvs = sorted(ctx.mft_out.glob("*_parsed.csv"))
    if mft_csvs:
        _keyword_sweep("MFT", mft_csvs, kw, ctx.keywords_out / "MFT", tools)

    registry_files = [p for p in ctx.registry_out.rglob("*") if p.is_file()]
    if registry_files:
        _keyword_sweep("Registry", registry_files, kw, ctx.keywords_out / "Registry", tools)

    if ctx.psort_file.is_file():
        _keyword_sweep("Plaso", [ctx.psort_file], kw, ctx.keywords_out / "Plaso", tools)
    else:
        log.info("[keywords] No psort available — Plaso search skipped.")

    if tools.has("hayabusa"):
        _run_hayabusa(ctx, tools, runner)
    else:
        log.warning("[easy] hayabusa missing — skipped.")

    if tools.has("chainsaw"):
        _run_chainsaw_hunt(ctx, tools, runner)
    else:
        log.warning("[easy] chainsaw missing — skipped.")

    runner.wait()


# ---------------------------------------------------------------------------
# Sysinfo
# ---------------------------------------------------------------------------

def extract_sysinfo(ctx: EvidenceContext) -> None:
    rip_system   = ctx.registry_out / "rip_SYSTEM.txt"
    rip_software = ctx.registry_out / "rip_SOFTWARE.txt"
    if not rip_system.is_file() or not rip_software.is_file():
        log.warning("[sysinfo] Missing RegRipper SYSTEM/SOFTWARE outputs.")
        return

    sys_text  = rip_system.read_text(encoding="utf-8", errors="replace")
    soft_text = rip_software.read_text(encoding="utf-8", errors="replace")

    def _first(text: str, key: str) -> str:
        m = re.search(rf"(?mi)^{re.escape(key)}\s*[:>\-]*\s*(.+)$", text)
        return m.group(1).strip() if m else ""

    ips: list[str] = []
    in_nic = False
    for line in sys_text.splitlines():
        if re.search(r"(?i)^\s*nic2", line):
            in_nic = True
            continue
        if in_nic and re.match(r"^-{10,}$", line.strip()):
            in_nic = False
            continue
        if in_nic and re.search(r"(?i)ipaddress", line):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m and m.group(1) != "0.0.0.0":
                ips.append(m.group(1))

    tz_name  = _first(sys_text, "TimeZoneKeyName")
    tz_bias_m = re.search(r"(?mi)^\s*Bias\s*->\s*(.+)$", sys_text)
    tz_bias  = tz_bias_m.group(1).strip() if tz_bias_m else ""
    tz       = f"{tz_name} → {tz_bias}" if (tz_name or tz_bias) else ""

    with ctx.sysinfo_file.open("w", encoding="utf-8") as fh:
        fh.write("System Information\n")
        fh.write(f"Hostname      : {_first(sys_text, 'ComputerName')}\n")
        fh.write(f"OS            : {_first(soft_text, 'ProductName')}\n")
        fh.write(f"IP            : {', '.join(ips)}\n")
        fh.write(f"Owner         : {_first(soft_text, 'RegisteredOwner')}\n")
        fh.write(f"Install Date  : {_first(soft_text, 'InstallDate')}\n")
        fh.write(f"Last Shutdown : {_first(sys_text, 'ShutdownTime')}\n")
        fh.write(f"TimeZone      : {tz}\n")

    log.info("[sysinfo] Written: %s", ctx.sysinfo_file)


# ---------------------------------------------------------------------------
# Keyword search
# ---------------------------------------------------------------------------

def _keyword_sweep(
    label: str,
    targets: list[Path],
    kw: KeywordsCfg,
    out_dir: Path,
    tools: ToolRegistry,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for custom in kw.custom_file:
        log.info("[keywords] %s custom list: %s", label, custom)
        search_keywords(custom, targets, out_dir, tools)
    log.info("[keywords] %s generic list", label)
    search_keywords(kw.generic_file, targets, out_dir, tools)


def search_keywords(
    keyword_file: Path,
    target_files: list[Path],
    out_dir: Path,
    tools: ToolRegistry,
) -> None:
    if not keyword_file.is_file():
        log.warning("[keywords] List not found: %s", keyword_file)
        return
    if not target_files:
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    grep_bin = tools.command("grep")

    with keyword_file.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            keyword = raw.rstrip("\n\r")
            if not keyword:
                continue
            safe = keyword.replace("/", "_").replace("\\", "_")[:200]
            if not safe:
                continue
            out_path = out_dir / safe
            cmd = [grep_bin, "-iaF", "--", keyword] + [str(t) for t in target_files]
            try:
                proc = subprocess.run(cmd, capture_output=True, check=False)
            except OSError as exc:
                log.debug("[keywords] grep failed for %r: %s", keyword, exc)
                continue
            if proc.stdout:
                out_path.write_bytes(proc.stdout)


# ---------------------------------------------------------------------------
# Hayabusa
# ---------------------------------------------------------------------------

def _run_hayabusa(ctx: EvidenceContext, tools: ToolRegistry, runner: TaskRunner) -> None:
    err_log = ctx.evtx_out / "error.log"
    hayabusa = tools.cmd_list("hayabusa")

    runner.submit(
        run_cmd,
        hayabusa + [
            "csv-timeline",
            "-C", "-w", "-q", "-Q",
            "--ISO-8601", "-U",
            "-p", "timesketch-verbose",
            "--directory", str(ctx.winevt_dir),
            "-o", str(ctx.evtx_out / "hayabusa_timeline.csv"),
        ],
        stdout_file=ctx.evtx_out / "hayabusa_timeline.stdout",
        stderr_file=err_log,
        append=True,
        label="hayabusa:csv-timeline",
    )

    runner.submit(
        run_cmd,
        hayabusa + [
            "logon-summary",
            "-q", "-Q", "--ISO-8601", "-U",
            "--directory", str(ctx.winevt_dir),
            "-o", str(ctx.evtx_out / "hayabusa_logon_summary"),
        ],
        stdout_file=ctx.evtx_out / "hayabusa_logon.stdout",
        stderr_file=err_log,
        append=True,
        label="hayabusa:logon-summary",
    )


# ---------------------------------------------------------------------------
# Chainsaw hunt
# ---------------------------------------------------------------------------

def _run_chainsaw_hunt(ctx: EvidenceContext, tools: ToolRegistry, runner: TaskRunner) -> None:
    err_log = ctx.evtx_out / "error.log"

    cmd = tools.cmd_list("chainsaw") + [
        "hunt",
        str(ctx.winevt_dir),
        "--rule", tools.command("chainsaw_rules"),
        "--csv", "--output", str(ctx.evtx_out / "chainsaw_hunt.csv"),
    ]

    mappings = tools.path("chainsaw_mappings")
    if mappings.is_file():
        cmd += ["--mapping", str(mappings)]

    sigma = tools.path("sigma_rules")
    if sigma.is_dir():
        cmd += ["--sigma", str(sigma)]

    runner.submit(
        run_cmd, cmd,
        stderr_file=err_log,
        append=True,
        label="chainsaw:hunt",
    )
