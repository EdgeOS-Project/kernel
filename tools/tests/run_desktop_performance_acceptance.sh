#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

exec python3 "$script_dir/desktop_performance_acceptance.py" \
    --webgl-page "$script_dir/desktop_webgl_acceptance.html" \
    "$@"
