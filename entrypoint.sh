#!/usr/bin/env bash
set -e

gcloud auth application-default login
python3 pykmstool.py "$@"
