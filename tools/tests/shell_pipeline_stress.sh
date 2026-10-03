#!/bin/sh
# Check fork, pipe ownership, command substitution, and child reaping together.
set -eu
limit=${1:-1000}
iteration=0
while [ "$iteration" -lt "$limit" ]; do
    actual=$(printf '%s\n' hello | tr l L | sed 's/h/H/')
    if [ "$actual" != HeLLo ]; then
        printf 'SHELL_PIPELINE_STRESS_FAIL iteration=%s value=%s\n' "$iteration" "$actual"
        exit 1
    fi
    iteration=$((iteration + 1))
done
printf 'SHELL_PIPELINE_STRESS_PASS count=%s\n' "$iteration"
