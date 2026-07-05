#!/usr/bin/env python3
"""
Hecatrace — DFIR Forensics Orchestrator
========================================
Entry point for the Windows forensic pipeline.
The business logic lives entirely in modules/.

Usage:
  python process_evidence.py -v --evidence /evidences/case_001 --output /output/case_001 -e
  python process_evidence.py -p mnt/ --evidence /evidences/case_002 -i disk.E01 --output /output/case_002 -e
  python process_evidence.py -v --evidence /evidences/case_001 --output /output/case_001 -s -e
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Optional

try:
    from rich.logging import RichHandler
    _RICH = True
except ImportError:
    _RICH = False

from modules import (
    load_config,
    build_context,
    ensure_output_tree,
    TaskRunner,
    ToolRegistry,
    Report,
    CollectorResult,
)
from modules.collectors import (
    collect_registry,
    collect_evtx,
    collect_mft,
    collect_usn,
    collect_ual,
    collect_strings,
    collect_plaso,
    collect_raw_image,
    run_easy_win,
)

DEFAULT_CONFIG  = Path("/opt/hecatrace/config/config.yaml")
DEFAULT_TOOLS   = Path("/opt/hecatrace/config/tools.yaml")
DEFAULT_ROUTING = Path("/opt/hecatrace/config/evtx_routing.yaml")

log = logging.getLogger("hecatrace")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(log_file: Path, verbose: bool) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    root.addHandler(file_handler)

    if _RICH:
        console: logging.Handler = RichHandler(
            level=level, show_path=False, show_time=True,
            rich_tracebacks=True, markup=False,
        )
    else:
        console = logging.StreamHandler()
        console.setLevel(level)
        console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    root.addHandler(console)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="process_evidence.py",
        description=(
            "Hecatrace — DFIR forensics orchestrator\n\n"
            "If -f/-v/-p are all omitted, the source type is auto-detected from "
            "--evidence: Velociraptor or FastIR layout, or a disk image "
            "(.dd/.raw/.img/.E01/.Ex01/.vhd/.vhdx/.vmdk/.aff) — in which case the "
            "image path and NTFS partition offset are auto-detected too."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Auto-detected source (Velociraptor, FastIR, or a disk image under --evidence)
  python process_evidence.py \\
      --evidence /evidences/case_001 --output /output/case_001 -e

  # Velociraptor collection (explicit)
  python process_evidence.py -v \\
      --evidence /evidences/case_001 --output /output/case_001 -e

  # Mounted raw image + disk image for Plaso
  python process_evidence.py -p mnt/ \\
      --evidence /evidences/case_002 -i disk.E01 --output /output/case_002 -e

  # Detection only (reuses existing processing)
  python process_evidence.py -v \\
      --evidence /evidences/case_001 --output /output/case_001 -s -e
        """,
    )

    # --- Source (mutually exclusive, optional — auto-detected from --evidence if omitted) ---
    src = parser.add_mutually_exclusive_group(required=False)
    src.add_argument(
        "-f", "--fastir", action="store_true",
        help="FastIR source — expects ./C/ under --evidence.",
    )
    src.add_argument(
        "-v", "--velociraptor", action="store_true",
        help="Velociraptor source — expects ./uploads/auto/C%%3A/ and ./uploads/ntfs/.",
    )
    src.add_argument(
        "-p", "--path", type=str, metavar="PATH",
        help="Generic mount point (path to the root of the Windows filesystem).",
    )

    # --- Paths ---
    parser.add_argument(
        "--evidence", type=str, default="/evidences",
        help="Evidence root (mounted volume). Default: /evidences.",
    )
    parser.add_argument(
        "--output", type=str, default="/output",
        help="Output directory. Default: /output.",
    )
    parser.add_argument(
        "--logs", type=str, default=None,
        help="Logs directory. Default: /logs (config.yaml).",
    )

    # --- Raw image ---
    parser.add_argument("-i", "--image",  type=str, help="Path to the raw / E01 image.")
    parser.add_argument("-o", "--offset", type=int, help="Partition offset (sectors).")

    # --- Pipeline control ---
    parser.add_argument(
        "-e", "--easy-win", action="store_true",
        help="Enables easy-win detection (Hayabusa, Chainsaw, keywords, sysinfo).",
    )
    parser.add_argument(
        "-s", "--skip-process", action="store_true",
        help="Skips the processing phase (useful with -e to rerun detection only).",
    )
    parser.add_argument(
        "--skip-plaso", action="store_true",
        help="Skips log2timeline / psort.",
    )
    parser.add_argument(
        "-r", "--reg-only", action="store_true",
        help="Processes only the registry hives, then exits.",
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Reruns log2timeline even if the .plaso file already exists.",
    )

    # --- Configuration ---
    parser.add_argument(
        "--config", type=str, default=str(DEFAULT_CONFIG),
        help=f"Path to config.yaml. Default: {DEFAULT_CONFIG}.",
    )
    parser.add_argument(
        "--tools", type=str, default=str(DEFAULT_TOOLS),
        help=f"Path to tools.yaml. Default: {DEFAULT_TOOLS}.",
    )
    parser.add_argument(
        "--routing", type=str, default=str(DEFAULT_ROUTING),
        help=f"Path to evtx_routing.yaml. Default: {DEFAULT_ROUTING}.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="DEBUG logging on the console.",
    )

    return parser


# ---------------------------------------------------------------------------
# Running a collector with timing and recording
# ---------------------------------------------------------------------------

def _collect(name: str, fn, *args, report: Report, **kwargs) -> None:
    """
    Wraps a collector: captures exceptions, measures duration,
    records the result in the report.
    `report` is consumed here and is not passed to fn.
    """
    start = time.monotonic()
    try:
        fn(*args, **kwargs)
        status, details = "ok", {}
    except Exception as exc:
        log.exception("[%s] Erreur inattendue : %s", name, exc)
        status, details = "error", {"error": str(exc)}
    report.add_collector(CollectorResult(
        name=name,
        status=status,
        duration_s=time.monotonic() - start,
        details=details,
    ))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Minimal logger before the log file path is available.
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # --- Configuration loading ---
    cfg   = load_config(Path(args.config))
    tools = ToolRegistry.load(Path(args.tools))

    # --- Checking tools inside the container ---
    missing_required, missing_optional = tools.check_all()
    if missing_optional:
        log.warning("Missing optional tools: %s", ", ".join(missing_optional))
    if missing_required:
        log.error("Required tools not found in the container:")
        for name in missing_required:
            log.error("    %s", name)
        return 2

    # --- Context construction (all paths resolved) ---
    try:
        ctx = build_context(args, cfg, tools)
    except ValueError as exc:
        log.error(str(exc))
        return 1

    ensure_output_tree(ctx)
    setup_logging(ctx.log_file, verbose=args.verbose)

    log.info("=== Hecatrace ===")
    log.info("Source    : %s", ctx.triage_type)
    log.info("Evidence  : %s", ctx.evidence_root)
    log.info("Base path : %s", ctx.base_path)
    log.info("Output    : %s", ctx.output_path)
    log.info("Raw mode  : %s", ctx.raw_mode)
    log.info("Workers   : %d", cfg.max_parallel_tasks)

    report = Report(str(ctx.evidence_root), str(ctx.output_path))
    report.missing_optional = missing_optional
    runner = TaskRunner(max_workers=cfg.max_parallel_tasks)

    try:
        if not args.skip_process:
            _collect("registry", collect_registry, ctx, tools, runner, report=report)

            if args.reg_only:
                log.info("--reg-only: stopping after registry.")
                return 0

            _collect("mft",    collect_mft,    ctx, tools, runner, report=report)
            _collect("evtx",   collect_evtx,   ctx, tools, runner, cfg,
                     routing_path=Path(args.routing), report=report)
            _collect("usn",    collect_usn,    ctx, tools, runner, report=report)
            _collect("strings", collect_strings, ctx, tools,        report=report)
            _collect("ual",    collect_ual,    ctx, tools, runner, report=report)

            if ctx.raw_mode:
                _collect("raw_image", collect_raw_image, ctx, tools, report=report)

            _collect("plaso", collect_plaso, ctx, cfg, tools,
                     skip=args.skip_plaso, overwrite=args.overwrite, report=report)

        if args.easy_win:
            _collect("easy_win", run_easy_win, ctx, tools, cfg, runner, report=report)

    finally:
        runner.shutdown()
        report.write(ctx.output_path / "report.json")

    log.info("=== Done. Results: %s ===", ctx.output_path)
    return 0


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _install_signal_handlers() -> None:
    def _handle(signum, _frame):
        log.warning("Signal %s received — clean shutdown.", signum)
        sys.exit(130)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle)
        except (ValueError, OSError):
            pass


if __name__ == "__main__":
    _install_signal_handlers()
    sys.exit(main())
