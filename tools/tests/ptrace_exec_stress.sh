#!/bin/sh
# Exercise exec transaction cleanup across more than 64 ptrace exec stops.
set -eu
round=0
while [ "$round" -lt 160 ]; do
    /bin/true
    round=$((round + 1))
done
printf 'PTRACE_EXEC_STRESS_PASS count=%s\n' "$round"
