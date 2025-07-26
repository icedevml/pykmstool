#!/usr/bin/env bash
set -e

if ! test -f /root/.config/gcloud/application_default_credentials.json; then
  gcloud auth application-default login --no-launch-browser
fi

/app/.venv/bin/python3 pykmstool.py "$@"
