#!/usr/bin/env python3
"""Check that pivot_root in a child does not rewrite the parent's fd paths."""
import ctypes
import os
import pathlib
import platform
import tempfile

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]

def checked(result, operation):
    if result < 0:
        raise OSError(ctypes.get_errno(), operation)

with tempfile.TemporaryDirectory(prefix="descriptor-pivot-", dir=".") as temporary:
    root = pathlib.Path(temporary).resolve() / "root"
    root.mkdir()
    (root / "old").mkdir()
    (root / "proc").mkdir()
    path = root / ("a" * 200) / ("b" * 200)
    path.mkdir(parents=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    child = os.fork()
    if child == 0:
        try:
            checked(libc.unshare(0x20000), "unshare mount")
            checked(libc.mount(None, b"/", None, 16384 | (1 << 18), None),
                    "make mounts private")
            checked(libc.mount(os.fsencode(root), os.fsencode(root), None,
                               4096, None), "bind new root")
            checked(libc.mount(b"/proc", os.fsencode(root / "proc"), None,
                               4096, None), "bind proc")
            pivot = 155 if platform.machine() == "x86_64" else 41
            checked(libc.syscall(pivot, os.fsencode(root), os.fsencode(root / "old")),
                    "pivot root")
            os.chdir("/")
            os.symlink("child", "link", dir_fd=descriptor)
            os.unlink("link", dir_fd=descriptor)
            os._exit(0)
        except BaseException as error:
            print(f"FAIL child: {error}", flush=True)
            os._exit(1)
    result = os.waitpid(child, 0)[1]
    actual = os.readlink(f"/proc/self/fd/{descriptor}")
    assert actual == str(path), ("parent", actual, str(path))
    os.symlink("parent", "link", dir_fd=descriptor)
    os.unlink("link", dir_fd=descriptor)
    os.close(descriptor)
    assert result == 0, result
print("PASS parent and child directory paths across pivot_root", flush=True)
