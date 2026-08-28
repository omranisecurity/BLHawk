#!/usr/bin/env bash
set -euo pipefail

# Resolve repository root regardless of where this script is invoked from.
cd "$(dirname "$0")/.."

# The default base image ships Python but not the venv/ensurepip support that
# `python3 -m venv` needs, so install it once if it is missing.
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq python3-venv
fi

python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
# flake8 and pytest are the lint/test tools the CI workflow relies on.
pip install flake8 pytest
