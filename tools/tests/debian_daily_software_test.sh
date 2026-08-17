#!/bin/sh
# Exercise a fixed set of common Debian command-line and desktop packages.

set -u

MODE=${1:-cli}
TIMEOUT_SECONDS=${EDGEOS_TEST_TIMEOUT:-20}
WORKDIR=${EDGEOS_TEST_WORKDIR:-/tmp/edgeos-daily-software-test}
RESULTS=${EDGEOS_TEST_RESULTS:-$WORKDIR/results.tsv}

mkdir -p "$WORKDIR"
: > "$RESULTS"

run_test() {
    number=$1
    package=$2
    shift 2
    started=$(date +%s%N)
    log="$WORKDIR/$number-$package.log"
    if timeout -k 2 "$TIMEOUT_SECONDS" sh -c "$*" >"$log" 2>&1; then
        status=PASS
    else
        rc=$?
        status="FAIL($rc)"
    fi
    ended=$(date +%s%N)
    elapsed_ms=$(((ended - started) / 1000000))
    printf '%s\t%s\t%s\t%s\n' "$number" "$package" "$status" "$elapsed_ms" |
        tee -a "$RESULTS"
}

run_cli_tests() {
    rm -rf "$WORKDIR/data"
    mkdir -p "$WORKDIR/data/find/sub"
    printf 'alpha beta\n' > "$WORKDIR/data/input.txt"
    printf 'nested\n' > "$WORKDIR/data/find/sub/nested.txt"
    python3 -c "import zipfile; z=zipfile.ZipFile('$WORKDIR/data/archive.zip', 'w'); z.write('$WORKDIR/data/input.txt', 'input.txt'); z.close()"

    run_test 1 bash "bash -c 'test \"\$(printf edgeos)\" = edgeos'"
    run_test 2 coreutils "printf edgeos | sha256sum | grep -Eq '^[0-9a-f]{64}  -$'"
    run_test 3 findutils "test \"\$(find '$WORKDIR/data/find' -type f -name nested.txt | wc -l)\" -eq 1"
    run_test 4 grep "grep -q 'alpha beta' '$WORKDIR/data/input.txt'"
    run_test 5 sed "test \"\$(sed 's/beta/kernel/' '$WORKDIR/data/input.txt')\" = 'alpha kernel'"
    run_test 6 gawk "test \"\$(printf '3 4\\n' | gawk '{print \$1 + \$2}')\" -eq 7"
    run_test 7 less "less --version | grep -q less"
    run_test 8 nano "nano --version | grep -q GNU"
    run_test 9 vim-tiny "vim.tiny --version | grep -q VIM"
    run_test 10 curl "curl -fsS --max-time 10 http://deb.debian.org/debian/README -o '$WORKDIR/data/curl-readme'; test -s '$WORKDIR/data/curl-readme'"
    run_test 11 wget "wget -q -T 10 -O '$WORKDIR/data/wget-readme' http://deb.debian.org/debian/README; test -s '$WORKDIR/data/wget-readme'"
    run_test 12 openssh-client "ssh -V 2>&1 | grep -q OpenSSH"
    run_test 13 rsync "mkdir -p '$WORKDIR/data/rsync'; rsync -a '$WORKDIR/data/input.txt' '$WORKDIR/data/rsync/'; cmp '$WORKDIR/data/input.txt' '$WORKDIR/data/rsync/input.txt'"
    run_test 14 git "rm -rf '$WORKDIR/data/repo'; git init -q '$WORKDIR/data/repo'; cd '$WORKDIR/data/repo'; git config user.email edgeos@example.invalid; git config user.name EdgeOS; printf tracked > tracked; git add tracked; git commit -qm test; test \"\$(git rev-list --count HEAD)\" -eq 1"
    run_test 15 unzip "unzip -t '$WORKDIR/data/archive.zip'"
    run_test 16 zip "cd '$WORKDIR/data'; zip -q archive.zip input.txt; test -s archive.zip"
    run_test 17 tar "tar -cf '$WORKDIR/data/archive.tar' -C '$WORKDIR/data' input.txt; tar -tf '$WORKDIR/data/archive.tar' | grep -qx input.txt"
    run_test 18 gzip "gzip -c '$WORKDIR/data/input.txt' | gzip -dc | cmp - '$WORKDIR/data/input.txt'"
    run_test 19 bzip2 "bzip2 -c '$WORKDIR/data/input.txt' | bzip2 -dc | cmp - '$WORKDIR/data/input.txt'"
    run_test 20 xz-utils "xz -c '$WORKDIR/data/input.txt' | xz -dc | cmp - '$WORKDIR/data/input.txt'"
    run_test 21 file "file '$WORKDIR/data/input.txt' | grep -q text"
    run_test 22 tree "tree '$WORKDIR/data/find' | grep -q nested.txt"
    run_test 23 jq "test \"\$(printf '{\"value\":42}' | jq -r .value)\" -eq 42"
    run_test 24 procps "ps -e -o pid=,comm= | grep -q '[[:space:]]systemd$'"
    run_test 25 iproute2 "ip -o addr show lo | grep -q '127.0.0.1/8'"
    run_test 26 iputils-ping "ping -c 1 -W 3 10.0.2.2 | grep -q '1 received'"
    run_test 27 bind9-dnsutils "dig +time=3 +tries=1 +short deb.debian.org A | grep -Eq '^[0-9]+(\\.[0-9]+){3}$'"
    run_test 28 netcat-openbsd "nc -z -w 5 deb.debian.org 80"
    run_test 29 python3 "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\", 0)); assert s.getsockname()[1] > 0; s.close()'"
    run_test 30 perl "perl -e 'print 6 * 7' | grep -qx 42"
    run_test 31 sqlite3 "rm -f '$WORKDIR/data/test.db'; sqlite3 '$WORKDIR/data/test.db' 'create table t(v); insert into t values(42);'; test \"\$(sqlite3 '$WORKDIR/data/test.db' 'select v from t;')\" -eq 42"
    run_test 32 tmux "tmux -L edgeos-test new-session -d -s daily; tmux -L edgeos-test display-message -p '#S' | grep -qx daily; tmux -L edgeos-test kill-server"
    run_test 33 htop "htop --version | grep -q htop"
    run_test 34 fastfetch "fastfetch --pipe | grep -qi EdgeOS"
    run_test 35 strace "strace -o '$WORKDIR/data/strace.log' /bin/true; grep -q exit_group '$WORKDIR/data/strace.log'"
    run_test 36 lsof "lsof -p 1 | grep -q COMMAND"
    run_test 37 man-db "mandb --version | grep -q man-db; mandb -c >/dev/null"
}

if [ "$MODE" = cli ]; then
    run_cli_tests
else
    printf 'unsupported mode: %s\n' "$MODE" >&2
    exit 2
fi

failures=$(awk -F '\t' '$3 ~ /^FAIL/ { count++ } END { print count + 0 }' "$RESULTS")
printf 'TOTAL=%s FAILURES=%s RESULTS=%s\n' "$(wc -l < "$RESULTS")" "$failures" "$RESULTS"
test "$failures" -eq 0
