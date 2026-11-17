#!/usr/bin/env bash
# One command: create a virtual environment, install, and start Case Replay.
#   ./run.sh            practice case + NIST case (if downloaded), then open http://127.0.0.1:8000
#   ./run.sh test       run the test suite
#   ./run.sh <command>  any casereplay command, e.g. ./run.sh run nist-data-leakage
set -e
cd "$(dirname "$0")"
PY="${PYTHON:-}"
for c in python3.13 python3.12 python3.11 python3; do
  if [ -z "$PY" ] && command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then PY="$c"; fi
done
if [ -z "$PY" ]; then echo "Python 3.11 or newer is required. On a Mac: brew install python@3.12"; exit 1; fi
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt
# Optional: Outlook mailboxes (OST and PST). It compiles from source on some systems, so it is best effort.
if ! .venv/bin/python -c "import pypff" >/dev/null 2>&1 && [ ! -f .venv/.pff_tried ]; then
  touch .venv/.pff_tried
  echo "Installing the optional mailbox reader (libpff-python). This can take a minute..."
  .venv/bin/python -m pip install -q libpff-python >/dev/null 2>&1 || echo "  not available here: email in Outlook mailboxes will be skipped"
fi
if [ "${1:-}" = "test" ]; then exec .venv/bin/python -m pytest -q; fi
if [ $# -eq 0 ]; then exec .venv/bin/python -m casereplay start; fi
exec .venv/bin/python -m casereplay "$@"
