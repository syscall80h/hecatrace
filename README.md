# Hecatrace

> All-in-one Docker-based DFIR forensics platform.  
> No host pollution. No dependency hell. One command to enter the environment.

---

## Overview

Hecatrace is a self-contained forensics container that packages every open-source tool needed for Windows digital forensics investigations (DFIR). It replaces the classic approach of installing tools on the analysis host with a single Docker image that is reproducible, isolated, and version-controlled.

**What lives inside the container:**

| Category | Tools |
|---|---|
| Timeline | Plaso / log2timeline, psort |
| EVTX | Hayabusa, Chainsaw + Sigma rules |
| Registry | RegRipper 4.0 |
| Filesystem | Sleuth Kit (fls, mactime, icat), analyzeMFT, INDXRipper |
| USN / UAL | USN-Journal-Parser, KStrike |
| Memory | Volatility3 |
| Malware | YARA, capa, FLOSS, Loki, oletools, pefile |
| Documents | pdfid, pdf-parser, oledump (Didier Stevens suite) |
| Carving | Foremost, Scalpel, Bulk Extractor, binwalk, PhotoRec |
| Imaging | ewf-tools (libewf), afflib-tools, dc3dd, hashdeep |
| Hashing | ssdeep, TLSH |
| Metadata | ExifTool, file, strings |
| Utilities | jq, ripgrep, 7zip, cabextract, ffmpeg, ClamAV |

**Host responsibilities (only three):**

1. Mount evidence volumes
2. Start the container
3. Collect results

---

## Architecture

```
hecatrace/
├── Dockerfile                  Multi-stage build (Ubuntu 22.04 LTS)
├── hecatrace                   Host-side CLI wrapper  ← main entry point
├── docker-compose.yml          Advanced interface (resource limits, CI/CD)
├── entrypoint.sh               Container entrypoint (shell / exec / pipeline)
├── process_evidence.py         Pipeline orchestrator (~200 lines)
├── requirements.txt
│
├── config/
│   ├── config.yaml             Global settings (paths, workers, Plaso tuning)
│   ├── tools.yaml              Tool registry - add a tool here, not in code
│   └── evtx_routing.yaml       EVTX → CSV routing - add an EventID here
│
├── modules/
│   ├── config.py               Config loader
│   ├── context.py              EvidenceContext (all paths, once resolved)
│   ├── runner.py               run_cmd() + TaskRunner (bounded parallelism)
│   ├── tools.py                ToolRegistry (reads tools.yaml)
│   ├── utils.py                Shared helpers
│   ├── report.py               JSON report writer
│   └── collectors/
│       ├── registry.py         RegRipper sweep
│       ├── evtx.py             Chainsaw dump + NDJSON → CSV splitter
│       ├── mft.py              analyzeMFT
│       ├── usn.py              USN-Journal-Parser
│       ├── ual.py              KStrike (UAL / MDB)
│       ├── strings.py          ASCII + UTF-16LE strings extraction
│       ├── plaso.py            log2timeline + psort
│       ├── raw_image.py        fls + INDXRipper + mactime
│       └── easy_win.py         Sysinfo, keywords, Hayabusa, Chainsaw hunt
│
└── resources/
    └── keywords/
        ├── generic_file.txt    Default file-based keyword list
        └── generic_image.txt   Default image-based keyword list
```

### Docker multi-stage build

| Stage | Role |
|---|---|
| `builder` | Downloads GitHub releases (Hayabusa, Chainsaw, capa, FLOSS) and git-clones Python tools. No binaries leak into the final image. |
| `final` | Clean Ubuntu 22.04 runtime. Installs apt packages, Python packages, copies tools from builder. |

---

## Prerequisites

- **Docker** 24+ (with BuildKit enabled)
- **SSH key** registered on GitHub (for `hecatrace shell` / git operations)

No Python, no pip, no virtualenv on the host.

---

## Quick Start

```bash
# 1. Clone and install the wrapper
git clone git@github.com:syscall80h/hecatrace.git
cd hecatrace
chmod +x hecatrace
ln -sf "$(pwd)/hecatrace" ~/bin/hecatrace

# 2. Build the image (first time only - ~25 min)
hecatrace build

# 3. Configure a workspace for a case
hecatrace init --evidence /srv/evidences/case_001 --output /srv/results/case_001

# 4. Enter the environment
hecatrace shell
```

Inside the shell, every tool is available directly:

```bash
process_evidence.py -v -e
volatility3 -f /evidences/mem.dmp windows.pslist
log2timeline.py --storage-file /output/plaso/case.plaso /evidences/mnt/
hayabusa csv-timeline --directory /evidences/evtx -o /output/timeline.csv
yara /opt/hecatrace/resources/rules.yar /evidences/
```

---

## Usage

### `hecatrace build`

Builds the Docker image from the project directory.

```bash
hecatrace build
hecatrace build hecatrace:2025.07        # custom tag
```

### `hecatrace init`

Configures a workspace for the current case. Creates `.hecatrace.env` in the current directory.

```bash
hecatrace init --evidence /srv/evidences/case_001 --output /srv/results/case_001
hecatrace init                           # interactive mode (prompts for paths)
```

The `.hecatrace.env` file stores:

```bash
HECATRACE_IMAGE=hecatrace:latest
HECATRACE_EVIDENCE=/srv/evidences/case_001
HECATRACE_OUTPUT=/srv/results/case_001
HECATRACE_LOGS=/srv/logs
```

> **One workspace per case.** Run `hecatrace init` from the case directory.

### `hecatrace shell`

Opens an interactive bash session inside the container with all volumes mounted.  
Equivalent to `source venv/bin/activate` for forensic environments.

```bash
hecatrace shell
# → bash inside the container
# → /evidences = HECATRACE_EVIDENCE (read-only)
# → /output    = HECATRACE_OUTPUT
# → all tools on PATH
```

Press `exit` or `Ctrl+D` to leave. The container is cleaned up automatically (`--rm`).

### `hecatrace run`

Runs `process_evidence.py` directly without entering the shell.

```bash
# Velociraptor collection - full pipeline
hecatrace run -v -e

# FastIR collection - registry only
hecatrace run -f -r

# Mounted image - skip processing, re-run detection only
hecatrace run -p mnt/ -s -e

# Raw image + Plaso + detection
hecatrace run -p mnt/ -i disk.E01 -e

# Overwrite existing Plaso file
hecatrace run -v -e --overwrite
```

**Key flags:**

| Flag | Description |
|---|---|
| `-v` / `--velociraptor` | Source is a Velociraptor collection |
| `-f` / `--fastir` | Source is a FastIR collection |
| `-p PATH` | Source is a generic mount point |
| `-i PATH` | Raw image path (for Plaso) |
| `-o OFFSET` | Partition offset in sectors |
| `-e` / `--easy-win` | Enable detection (Hayabusa, Chainsaw, keywords) |
| `-s` / `--skip-process` | Skip processing, run detection only |
| `--skip-plaso` | Skip log2timeline / psort |
| `-r` / `--reg-only` | Registry parsing only |
| `--overwrite` | Re-run log2timeline even if `.plaso` exists |
| `--verbose` | DEBUG logging |

### `hecatrace exec`

Runs any tool in the container as a one-shot command.

```bash
hecatrace exec volatility3 -f /evidences/mem.dmp windows.pslist
hecatrace exec chainsaw hunt /evidences/evtx --rule /opt/hecatrace/tools/chainsaw/rules
hecatrace exec yara /opt/hecatrace/resources/rules.yar /evidences/suspicious/
hecatrace exec exiftool /evidences/images/
hecatrace exec foremost -t all -i /evidences/disk.E01 -o /output/carving/
```

### `hecatrace status`

Shows the image status and current workspace configuration.

```bash
hecatrace status
```

### `hecatrace update`

Pulls the latest version from git and rebuilds the image.

```bash
hecatrace update
```

---

## Pipeline

When `process_evidence.py` runs, it executes the following collectors in order:

| Collector | Input | Output |
|---|---|---|
| `registry` | SAM, SOFTWARE, SYSTEM, NTUSER.DAT, USRCLASS.DAT, AmCache | `output/registry/` |
| `mft` | $MFT | `output/mft/*.csv` |
| `evtx` | Windows Event Logs (.evtx) | `output/evtx/*.csv` + `evtx.ndjson` |
| `usn` | $UsnJrnl:$J | `output/usn/*.csv` |
| `strings` | pagefile.sys, hiberfil.sys (raw) or all files | `output/strings/everything.strings` |
| `ual` | UAL .mdb files (Windows Server only) | `output/ual/*.psv` |
| `raw_image` | Raw disk image | `output/mft/fls.bodyfile`, `fls.timeline` |
| `plaso` | Evidence root or raw image | `output/plaso/evidence.plaso`, `output.psort` |
| `easy_win` | Registry + MFT + Plaso outputs, EVTX directory | `output/systeminfo.txt`, `output/keywords/`, `output/evtx/hayabusa_*`, `output/evtx/chainsaw_hunt.csv` |

A `report.json` is always written to `output/` at the end, even on failure.

### EVTX routing

The EVTX collector dumps all event logs to NDJSON (single Chainsaw pass) then splits into per-EventID CSVs in a **single Python pass** - replacing the original 25 `grep | jq` invocations.

Routing is driven by `config/evtx_routing.yaml`. No code change needed to add a new EventID.

---

## Configuration

### `config/config.yaml`

Global settings. Paths can be overridden via environment variables.

```yaml
max_parallel_tasks: 6            # subprocess parallelism

plaso:
  worker_memory_limit: 4294967296
  parsers: win7_slow
  storage_filename: evidence.plaso
  psort_filename: output.psort

keywords:
  generic_file:  keywords/generic_file.txt
  generic_image: keywords/generic_image.txt
  custom_file:   []              # per-case IOC lists
  custom_image:  []
```

| Env var | Overrides |
|---|---|
| `HECATRACE_EVIDENCE_ROOT` | `evidence_root` |
| `HECATRACE_OUTPUT_ROOT` | `output_root` |
| `HECATRACE_LOGS_ROOT` | `logs_root` |

### `config/tools.yaml`

Registry of every tool in the container. Adding a tool here makes it available to all collectors via `tools.cmd_list("name")`.

```yaml
tools:
  my_tool:
    command:     /opt/hecatrace/tools/my_tool/my_tool
    type:        binary          # binary | python | perl
    optional:    true
    description: "My custom tool"
```

### `config/evtx_routing.yaml`

Controls which Windows EventIDs are extracted and which fields are written to CSV.

```yaml
routes:
  - event_id:    4688
    channel:     "Security"
    output_file: "4688_process_creation.csv"
    fields:
      - SubjectUserName
      - NewProcessName
      - CommandLine
```

---

## Extending Hecatrace

### Add a new forensic tool

1. Add the download/install step to `Dockerfile` (builder or final stage)
2. Add an entry to `config/tools.yaml`
3. Use it in a collector: `tools.cmd_list("my_tool")`

No changes to `process_evidence.py` required for tools used inline.

### Add a new EVTX EventID

Add an entry to `config/evtx_routing.yaml`. No code change needed.

### Add a new collector module

1. Create `modules/collectors/my_collector.py`
2. Implement `def collect_my_thing(ctx, tools, runner) -> None`
3. Register it in `modules/collectors/__init__.py`
4. Add the call to `process_evidence.py`

---

## Evidence Sources

| Source | Flag | Expected structure |
|---|---|---|
| Velociraptor | `-v` | `uploads/auto/C%3A/` + `uploads/ntfs/` |
| FastIR | `-f` | `C/` |
| Mounted image | `-p PATH` | Any Windows filesystem root |
| Raw image (Plaso) | `-p PATH -i IMAGE` | Mount point + raw image |

---

## Output Structure

```
output/
├── registry/
│   ├── rip_SAM.txt
│   ├── rip_SOFTWARE.txt
│   ├── rip_SYSTEM.txt
│   ├── rip_amcache.txt
│   ├── ntuser/
│   └── usrclass/
├── evtx/
│   ├── evtx.ndjson
│   ├── 4624_logon.csv
│   ├── 4625_logon_failed.csv
│   ├── 4688_process_creation.csv
│   ├── hayabusa_timeline.csv
│   ├── chainsaw_hunt.csv
│   └── ...
├── mft/
│   ├── MFT_parsed.csv
│   ├── fls.bodyfile        (raw mode)
│   └── fls.timeline        (raw mode)
├── usn/
├── strings/
├── ual/
├── plaso/
│   ├── evidence.plaso
│   └── output.psort
├── keywords/
│   ├── MFT/
│   ├── Registry/
│   └── Plaso/
├── systeminfo.txt
└── report.json             ← always written, even on failure
```

---

## License

MIT - see [LICENSE](LICENSE).

---

*Hecatrace is named after Hecate, the Greek goddess of crossroads, magic, and the night - a fitting patron for digital forensics work.*
