#!/usr/bin/env python3
"""Exercise full-length directory descriptor paths across dup, fork, and close."""
import os
import pathlib
import tempfile

with tempfile.TemporaryDirectory(prefix="descriptor-path-", dir=".") as directory:
    path = pathlib.Path(directory).resolve()
    for depth in range(12):
        path /= chr(ord("a") + depth) * 240
        path.mkdir()
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        duplicate = os.dup(descriptor)
        os.close(descriptor)
        assert os.readlink(f"/proc/self/fd/{duplicate}") == str(path)
        child = os.fork()
        if child == 0:
            try:
                os.symlink("target", "link", dir_fd=duplicate)
                assert os.readlink("link", dir_fd=duplicate) == "target"
                os.unlink("link", dir_fd=duplicate)
                os.close(duplicate)
                os._exit(0)
            except BaseException as error:
                print(f"FAIL child: {error}", flush=True)
                os._exit(1)
        assert os.waitpid(child, 0)[1] == 0
        os.symlink("parent", "link", dir_fd=duplicate)
        assert os.readlink("link", dir_fd=duplicate) == "parent"
        os.unlink("link", dir_fd=duplicate)
        os.close(duplicate)
        print(f"PASS directory length={len(str(path))}", flush=True)
print("PASS full directory descriptor paths", flush=True)
