from __future__ import annotations

import argparse
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import Config
from .tools import ToolRegistry

log = logging.getLogger("hecatrace.context")

TRIAGE_VELOCIRAPTOR = "velociraptor"
TRIAGE_FASTIR = "fastir"
TRIAGE_MOUNT = "mount"

VELO_UPLOAD_C   = "uploads/auto/C%3A/"
VELO_UPLOAD_MFT = "uploads/ntfs"
FAST_IR_C       = "C/"

BASE_AMCACHE_PATH = "Windows/appcompat/Programs/"
AMCACHE_FNAME     = "amcache.hve"
BASE_CONFIG_PATH  = "Windows/System32/config/"
BASE_USER_PATH    = "Users"
BASE_WINEVT_PATH  = "Windows/System32/winevt/Logs/"
BASE_UAL_PATH     = "Windows/System32/LogFiles/Sum/"
HIVES = ("SAM", "SOFTWARE", "SYSTEM")

# Disk image container formats recognized for auto-detection.
# All are read natively by Sleuth Kit (mmls/fls/img_stat) without mounting.
RAW_IMAGE_EXTENSIONS = (
    ".dd", ".raw", ".img", ".e01", ".ex01", ".s01",
    ".vhd", ".vhdx", ".vmdk", ".aff",
)


@dataclass
class EvidenceContext:
    """Centralizes all pipeline paths once the triage type has been resolved."""
    triage_type: str
    raw_mode: bool
    image_path: Optional[Path]
    offset: Optional[int]
    evidence_root: Path
    base_path: Path
    mft_path: Path
    output_path: Path
    amcache_dir: Path
    config_dir: Path
    user_dir: Path
    winevt_dir: Path
    ual_dir: Path
    registry_out: Path
    evtx_out: Path
    mft_out: Path
    usn_out: Path
    strings_out: Path
    ual_out: Path
    plaso_out: Path
    plaso_file: Path
    psort_file: Path
    keywords_out: Path
    sysinfo_file: Path
    log_file: Path


# ---------------------------------------------------------------------------
# Auto-detection (used when -f/-v/-p are all omitted)
# ---------------------------------------------------------------------------

def _walk_bounded(root: Path, max_depth: int):
    """Yields (dirpath, dirnames, filenames) top-down, pruning below max_depth
    so large mounted evidence trees aren't walked in full."""
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        yield Path(dirpath), dirnames, filenames


def _find_mounted_windows_root(root: Path, max_depth: int = 3) -> Optional[Path]:
    """Looks for an already-mounted Windows tree (a directory containing
    Windows/System32/config) up to max_depth levels under root."""
    if not root.is_dir():
        return None
    if (root / BASE_CONFIG_PATH).is_dir():
        return root
    for dirpath, dirnames, _ in _walk_bounded(root, max_depth):
        for name in list(dirnames):
            if name.lower() == "windows" and (dirpath / name / "System32" / "config").is_dir():
                return dirpath
    return None


def _find_raw_image(root: Path, max_depth: int = 2) -> Optional[Path]:
    """Looks for a disk image file (RAW_IMAGE_EXTENSIONS) under root, stopping
    at max_depth so large evidence trees aren't scanned in full."""
    if not root.is_dir():
        return None
    hits: list[Path] = []
    for dirpath, _, filenames in _walk_bounded(root, max_depth):
        for name in filenames:
            if Path(name).suffix.lower() in RAW_IMAGE_EXTENSIONS:
                hits.append(dirpath / name)
    if not hits:
        return None
    hits.sort(key=lambda p: (len(p.relative_to(root).parts), str(p)))
    return hits[0]


_MMLS_LINE_RE = re.compile(
    r"^\d{3}:\s+\S+\s+(\d+)\s+\d+\s+\d+\s+(.+)$"
)
_NTFS_DESCRIPTION_RE = re.compile(r"ntfs|exfat|basic data partition", re.IGNORECASE)


def detect_ntfs_offset(image_path: Path, tools: ToolRegistry) -> Optional[int]:
    """Runs mmls on image_path and returns the start sector of the first
    NTFS/exFAT (or GPT 'Basic data') partition found, or None if mmls is
    unavailable or no matching partition is found."""
    if not tools.has("mmls"):
        log.warning("[context] mmls unavailable — cannot auto-detect the partition offset.")
        return None
    try:
        proc = subprocess.run(
            tools.cmd_list("mmls") + [str(image_path)],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("[context] mmls failed on %s: %s", image_path, exc)
        return None

    for line in proc.stdout.splitlines():
        m = _MMLS_LINE_RE.match(line.strip())
        if not m:
            continue
        start_sector, description = m.groups()
        if _NTFS_DESCRIPTION_RE.search(description):
            return int(start_sector)
    return None


def build_context(args: argparse.Namespace, cfg: Config, tools: ToolRegistry) -> EvidenceContext:
    evidence_root = Path(args.evidence).resolve()
    output_path   = Path(args.output).resolve()

    logs_root = Path(getattr(args, "logs", None) or cfg.logs_root)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if args.fastir:
        triage = TRIAGE_FASTIR
        base   = evidence_root / FAST_IR_C
        mft    = base
        raw    = False
    elif args.velociraptor:
        triage = TRIAGE_VELOCIRAPTOR
        base   = evidence_root / VELO_UPLOAD_C
        mft    = evidence_root / VELO_UPLOAD_MFT
        raw    = False
    elif args.path:
        triage = TRIAGE_MOUNT
        p = Path(args.path)
        base = p if p.is_absolute() else (evidence_root / p)
        mft  = base
        raw  = True
    elif (evidence_root / VELO_UPLOAD_C).is_dir() or (evidence_root / VELO_UPLOAD_MFT).is_dir():
        triage = TRIAGE_VELOCIRAPTOR
        base   = evidence_root / VELO_UPLOAD_C
        mft    = evidence_root / VELO_UPLOAD_MFT
        raw    = False
        log.info("Auto-detected source: Velociraptor")
    elif (evidence_root / FAST_IR_C).is_dir():
        triage = TRIAGE_FASTIR
        base   = evidence_root / FAST_IR_C
        mft    = base
        raw    = False
        log.info("Auto-detected source: FastIR")
    else:
        image_candidate = _find_raw_image(evidence_root)
        if image_candidate is None:
            raise ValueError(
                f"Could not auto-detect the evidence type under {evidence_root} "
                "(no Velociraptor/FastIR layout and no disk image found). "
                "Use -f, -v or -p to specify it explicitly."
            )
        triage = TRIAGE_MOUNT
        raw = True
        mounted = _find_mounted_windows_root(evidence_root)
        base = mounted if mounted is not None else evidence_root
        mft = base
        if not args.image:
            args.image = str(image_candidate)
        log.info("Auto-detected source: disk image (%s)", image_candidate.name)
        if mounted is None:
            log.warning(
                "No mounted Windows filesystem found alongside the image — "
                "registry/EVTX/MFT/UAL/strings collectors will be skipped. "
                "Mount the image and pass -p <mountpoint> to run them."
            )

    image_path: Optional[Path] = None
    if args.image:
        p = Path(args.image)
        image_path = p if p.is_absolute() else (evidence_root / p).resolve()

    offset = args.offset
    if raw and image_path is not None and offset is None:
        offset = detect_ntfs_offset(image_path, tools)
        if offset is not None:
            log.info("Auto-detected partition offset: %d (sectors)", offset)
        else:
            log.warning(
                "Could not auto-detect a partition offset for %s — "
                "pass -o manually if fls/INDXRipper need it.", image_path,
            )

    return EvidenceContext(
        triage_type=triage,
        raw_mode=raw,
        image_path=image_path,
        offset=offset,
        evidence_root=evidence_root,
        base_path=base.resolve(),
        mft_path=mft.resolve(),
        output_path=output_path,
        amcache_dir=base / BASE_AMCACHE_PATH,
        config_dir=base / BASE_CONFIG_PATH,
        user_dir=base / BASE_USER_PATH,
        winevt_dir=base / BASE_WINEVT_PATH,
        ual_dir=base / BASE_UAL_PATH,
        registry_out=output_path / "registry",
        evtx_out=output_path / "evtx",
        mft_out=output_path / "mft",
        usn_out=output_path / "usn",
        strings_out=output_path / "strings",
        ual_out=output_path / "ual",
        plaso_out=output_path / "plaso",
        plaso_file=output_path / "plaso" / cfg.plaso.storage_filename,
        psort_file=output_path / "plaso" / cfg.plaso.psort_filename,
        keywords_out=output_path / "keywords",
        sysinfo_file=output_path / "systeminfo.txt",
        log_file=logs_root / f"hecatrace_{timestamp}.log",
    )


def ensure_output_tree(ctx: EvidenceContext) -> None:
    for d in [
        ctx.output_path,
        ctx.registry_out / "ntuser",
        ctx.registry_out / "usrclass",
        ctx.evtx_out,
        ctx.plaso_out,
        ctx.mft_out,
        ctx.usn_out,
        ctx.strings_out,
        ctx.ual_out,
        ctx.keywords_out,
        ctx.log_file.parent,
    ]:
        d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Filesystem helpers (case tolerance — Windows sources)
# ---------------------------------------------------------------------------

def find_case_insensitive(root: Path, subpath: str, filename: str) -> list[Path]:
    """Finds filename under root/subpath/... tolerating case differences."""
    if not root.is_dir():
        return []
    target_dir = root / subpath
    if target_dir.is_dir():
        hits = [p for p in target_dir.rglob("*")
                if p.is_file() and p.name.lower() == filename.lower()]
        if hits:
            return hits
    return [p for p in root.rglob(filename)
            if p.is_file() and p.name.lower() == filename.lower()]


def find_ci_file(directory: Path, filename: str) -> Optional[Path]:
    """Returns the first file matching filename (case-insensitive)."""
    if not directory.is_dir():
        return None
    target = filename.lower()
    for child in directory.iterdir():
        if child.is_file() and child.name.lower() == target:
            return child
    return None


def find_usrclass(user_dir: Path) -> Optional[Path]:
    """Finds UsrClass.dat under AppData\\Local\\Microsoft\\Windows\\ (case-insensitive)."""
    candidate = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
    if candidate.is_file():
        return candidate
    for path in user_dir.rglob("UsrClass.dat"):
        if path.is_file():
            return path
    for path in user_dir.rglob("usrclass.dat"):
        if path.is_file():
            return path
    return None
