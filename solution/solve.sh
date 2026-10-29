#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${APP_DIR}/runtime"
cp "${SCRIPT_DIR}/agent.py" "${APP_DIR}/runtime/agent.py"
