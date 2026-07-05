from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from ..config import Config
from ..context import EvidenceContext
from ..runner import TaskRunner, run_cmd
from ..tools import ToolRegistry
from ..utils import delete_empty_files, report_empty

log = logging.getLogger("hecatrace.evtx")

DEFAULT_ROUTING_PATH = Path("/opt/hecatrace/config/evtx_routing.yaml")

# Route : (channel_substr, output_file, fields)
Route = tuple[str, str, list[str]]
RoutingTable = dict[int, list[Route]]


def load_routing(path: Path = DEFAULT_ROUTING_PATH) -> RoutingTable:
    """Loads the EVTX routing table from the YAML file."""
    if not path.is_file():
        log.warning("[evtx] Routing file not found: %s", path)
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    routing: RoutingTable = {}
    for route in data.get("routes", []):
        eid = int(route["event_id"])
        entry: Route = (
            route.get("channel", ""),
            route["output_file"],
            route.get("fields", []),
        )
        routing.setdefault(eid, []).append(entry)
    log.debug("[evtx] %d EventIDs loaded from %s", len(routing), path)
    return routing


# ---------------------------------------------------------------------------
# EVTX field parsers (format produced by Chainsaw dump --jsonl)
# ---------------------------------------------------------------------------

def _evtx_field(event: dict, *keys: str, default: str = "") -> str:
    cur: Any = event
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    if isinstance(cur, (dict, list)):
        return json.dumps(cur, ensure_ascii=False)
    return "" if cur is None else str(cur)


def _get_event_id(event: dict) -> Optional[int]:
    ev = event.get("Event") or event
    system = ev.get("System", {}) if isinstance(ev, dict) else {}
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text") or eid.get("Value")
    try:
        return int(eid) if eid is not None else None
    except (TypeError, ValueError):
        return None


def _get_channel(event: dict) -> str:
    ev = event.get("Event") or event
    return _evtx_field(ev, "System", "Channel") or _evtx_field(ev, "System", "Provider", "@Name")


def _get_provider(event: dict) -> str:
    ev = event.get("Event") or event
    return _evtx_field(ev, "System", "Provider", "@Name")


def _get_datetime(event: dict) -> str:
    ev = event.get("Event") or event
    ts = ev.get("System", {}).get("TimeCreated") if isinstance(ev, dict) else {}
    if isinstance(ts, dict):
        return ts.get("@SystemTime", "")
    return ""


def _get_data(event: dict, name: str) -> str:
    ev = event.get("Event") or event
    data = ev.get("EventData")
    if isinstance(data, dict):
        items = data.get("Data")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("@Name") == name:
                    return str(item.get("#text", ""))
        elif isinstance(items, dict) and items.get("@Name") == name:
            return str(items.get("#text", ""))
    return ""


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

def collect_evtx(
    ctx: EvidenceContext,
    tools: ToolRegistry,
    runner: TaskRunner,
    cfg: Config,
    routing_path: Path = DEFAULT_ROUTING_PATH,
) -> None:
    if not ctx.winevt_dir.is_dir():
        log.warning("[evtx] winevt directory missing: %s", ctx.winevt_dir)
        return

    routing = load_routing(routing_path)
    ndjson_path = ctx.evtx_out / "evtx.ndjson"
    err_log = ctx.evtx_out / "error.log"

    log.info("[evtx] Chainsaw dump → NDJSON")
    result = run_cmd(
        tools.cmd_list("chainsaw") + [
            "dump", "--jsonl",
            "--output", str(ndjson_path),
            str(ctx.winevt_dir),
        ],
        stderr_file=err_log,
        append=True,
        label="chainsaw:dump",
    )
    if not result.ok or not ndjson_path.is_file():
        log.error("[evtx] Chainsaw dump failed — aborting split.")
        return

    log.info("[evtx] Splitting NDJSON by EventID")
    events_total, events_routed = split_evtx_by_eventid(ndjson_path, ctx.evtx_out, routing)

    # Optional internal parsers
    for key in ("rdp_session_parser", "security_session_parser"):
        script = cfg.internal_tools.get(key) or ""
        if script and Path(script).is_file():
            run_cmd(
                ["python3", script, "-f", str(ndjson_path), "-o", str(ctx.evtx_out)],
                stderr_file=err_log, append=True, label=key,
            )

    delete_empty_files(ctx.evtx_out, ignore=("error.log", "evtx.ndjson"))
    report_empty(ctx.evtx_out, "evtx", ignore=("error.log", "evtx.ndjson"))
    log.info("[evtx] %d events processed, %d routed", events_total, events_routed)


def split_evtx_by_eventid(
    ndjson_path: Path,
    out_dir: Path,
    routing: RoutingTable,
) -> tuple[int, int]:
    """
    Single pass over the NDJSON → CSVs per EventID.
    Returns (total_events, routed_events).
    """
    open_writers: dict[str, tuple[Any, Any]] = {}

    def _writer(filename: str) -> csv.writer:
        if filename not in open_writers:
            f = open(out_dir / filename, "w", newline="", encoding="utf-8")
            open_writers[filename] = (f, csv.writer(f, quoting=csv.QUOTE_MINIMAL))
        return open_writers[filename][1]

    total = routed = 0
    with open(ndjson_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            eid = _get_event_id(event)
            if eid is None or eid not in routing:
                continue

            chan_haystack = f"{_get_channel(event)} {_get_provider(event)}"
            for channel_substr, output_file, fields in routing[eid]:
                if channel_substr and channel_substr not in chan_haystack:
                    continue
                row = [_get_datetime(event), _get_provider(event), str(eid)]
                row.extend(_get_data(event, f) for f in fields)
                _writer(output_file).writerow(row)
                routed += 1

    for f, _ in open_writers.values():
        f.close()
    return total, routed
