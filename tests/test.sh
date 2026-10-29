#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
mkdir -p /logs/verifier
export APP_DIR
export PYTHONPATH="${APP_DIR}${PYTHONPATH:+:$PYTHONPATH}"
cd "${APP_DIR}"

set +e
python3 /tests/test_runtime.py
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
exit 0
