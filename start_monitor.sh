#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PYTHON_BIN="${PYTHON_BIN:-python}"
mkdir -p data static

# Start the independent collector. Its file lock prevents duplicate collectors.
"$PYTHON_BIN" collector.py --loop >> data/collector.log 2>&1 &
COLLECTOR_PID=$!

cleanup() {
  kill "$COLLECTOR_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Static serving is required only so the small Streamlit loader can fetch the
# cached HTML/version files. All user-editable settings remain in ./config/.
"$PYTHON_BIN" -m streamlit run GPUMonitor.py --server.enableStaticServing=true
