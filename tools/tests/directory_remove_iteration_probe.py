#!/usr/bin/env python3
"""Delete entries during a multi-buffer readdir scan without skipping names."""
import os
import pathlib
import tempfile

with tempfile.TemporaryDirectory(prefix="directory-cookies-", dir=".") as directory:
    root = pathlib.Path(directory)
    for index in range(1800):
        (root / f"entry-{index:06d}").touch()
    removed = 0
    with os.scandir(root) as entries:
        for entry in entries:
            os.unlink(entry.path)
            removed += 1
    remaining = list(root.iterdir())
    assert not remaining, (removed, len(remaining), [path.name for path in remaining[:5]])
print("PASS removed 1800 entries during one directory scan", flush=True)
