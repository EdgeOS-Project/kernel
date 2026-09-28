#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

directory=/tmp/edgeos-vfs-dynamic-cache
echo "EDGE_VFS_DYNAMIC_CACHE_STAGE initial_cleanup"
if [ -e "$directory" ]; then
    echo "EDGE_VFS_DYNAMIC_CACHE_STAGE initial_directory_present"
else
    echo "EDGE_VFS_DYNAMIC_CACHE_STAGE initial_directory_absent"
fi
rm -rf "$directory"
echo "EDGE_VFS_DYNAMIC_CACHE_STAGE initial_cleanup_complete"
mkdir -p "$directory"

python3 - "$directory" <<'PY'
import os
import shutil
import sys
import time

root = sys.argv[1]
count = 5000
started = time.monotonic()

for index in range(count):
    path = os.path.join(root, f"entry-{index}")
    with open(path, "wb") as stream:
        stream.write(index.to_bytes(4, "little"))
created = time.monotonic()
print("EDGE_VFS_DYNAMIC_CACHE_STAGE create_complete", flush=True)

for pass_number in range(2):
    for index in range(count):
        path = os.path.join(root, f"entry-{index}")
        status = os.stat(path)
        assert status.st_size == 4
statted = time.monotonic()
print("EDGE_VFS_DYNAMIC_CACHE_STAGE stat_complete", flush=True)

handles = [
    open(os.path.join(root, f"entry-{index}"), "rb")
    for index in range(600)
]
for index, stream in enumerate(handles):
    assert stream.read() == index.to_bytes(4, "little")
for stream in handles:
    stream.close()
opened = time.monotonic()
print("EDGE_VFS_DYNAMIC_CACHE_STAGE open_complete", flush=True)

for index in range(0, count, 3):
    os.unlink(os.path.join(root, f"entry-{index}"))

for index in range(count):
    path = os.path.join(root, f"entry-{index}")
    if index % 3 == 0:
        try:
            os.stat(path)
        except FileNotFoundError:
            continue
        raise AssertionError(f"removed path still resolved: {path}")
    assert os.stat(path).st_size == 4

verified = time.monotonic()
print("EDGE_VFS_DYNAMIC_CACHE_STAGE delete_verify_complete", flush=True)
shutil.rmtree(root)
cleaned = time.monotonic()
print("EDGE_VFS_DYNAMIC_CACHE_STAGE cleanup_complete", flush=True)
print(
    "EDGE_VFS_DYNAMIC_CACHE_TIMING "
    f"create={created - started:.3f} "
    f"stat={statted - created:.3f} "
    f"open={opened - statted:.3f} "
    f"delete_verify={verified - opened:.3f} "
    f"cleanup={cleaned - verified:.3f}"
)
print("EDGE_VFS_DYNAMIC_CACHE_PASS")
PY
