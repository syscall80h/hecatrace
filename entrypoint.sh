#!/usr/bin/env bash
# =============================================================================
# Hecatrace - container entrypoint
# =============================================================================
# Modes:
#   shell / bash      → opens an interactive shell
#   exec <cmd> <args> → runs an arbitrary command in the container
#   <flags...>        → delegates to process_evidence.py (default behavior)
# =============================================================================
set -euo pipefail

PROCESS_EVIDENCE="/opt/hecatrace/process_evidence.py"

case "${1:-}" in
    shell|bash)
        exec /bin/bash --login
        ;;
    exec)
        shift
        exec "$@"
        ;;
    "")
        exec python3 "$PROCESS_EVIDENCE" --help
        ;;
    *)
        exec python3 "$PROCESS_EVIDENCE" "$@"
        ;;
esac
