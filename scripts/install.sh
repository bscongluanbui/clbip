#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo 'Install Python 3, Docker Engine and Docker Compose v2 first.' >&2; exit 1; }
exec python3 "$HERE/install.py" "$@"
