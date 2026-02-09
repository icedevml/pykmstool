#!/usr/bin/env bash
set -e

if [ "$1" = "docker-revoke-credentials" ];
then
  gcloud auth application-default revoke
  rm -rf /root/.config/gcloud/application_default_credentials.json
  exit 0
fi

if ! test -f /root/.config/gcloud/application_default_credentials.json; then
  gcloud auth application-default login --no-launch-browser
fi

/app/.venv/bin/pykmstool "$@"
