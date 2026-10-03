#!/usr/bin/env python3
"""Check nsfs path/fd statfs parity and GNU df in a private Linux mount namespace."""
import ctypes
import errno
import os
import subprocess
import tempfile


class Statfs(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_long), ("bsize", ctypes.c_long),
        ("blocks", ctypes.c_ulong), ("bfree", ctypes.c_ulong),
        ("bavail", ctypes.c_ulong), ("files", ctypes.c_ulong),
        ("ffree", ctypes.c_ulong), ("fsid", ctypes.c_int * 2),
        ("namelen", ctypes.c_long), ("frsize", ctypes.c_long),
        ("flags", ctypes.c_long), ("spare", ctypes.c_long * 4),
    ]


def main():
    if os.uname().sysname != "Linux" or ctypes.sizeof(ctypes.c_long) != 8:
        raise SystemExit("Requires a 64-bit Linux ABI guest")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_void_p]
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(Statfs)]
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(Statfs)]

    def checked(result):
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    def fetch(path=None, fd=None):
        result = Statfs()
        if fd is None:
            checked(libc.statfs(os.fsencode(path), ctypes.byref(result)))
        else:
            checked(libc.fstatfs(fd, ctypes.byref(result)))
        return result

    # Fail on missing privileges; never mount into the caller's namespace.
    checked(libc.unshare(0x00020000))  # CLONE_NEWNS
    checked(libc.mount(None, b"/", None, (1 << 14) | (1 << 18), None))
    with tempfile.TemporaryDirectory(prefix="edgeos-nsfs-statfs-") as directory:
        target = os.path.join(directory, "cups.mnt")
        with open(target, "wb"):
            pass
        underlying = fetch(path=target)
        checked(libc.mount(b"/proc/self/ns/mnt", os.fsencode(target),
                           None, 4096, None))
        mounted = True
        try:
            for flags in (os.O_RDONLY, os.O_PATH):
                fd = os.open(target, flags)
                direct = os.open("/proc/self/ns/mnt", os.O_RDONLY)
                try:
                    values = [fetch(path=target), fetch(fd=fd), fetch(fd=direct)]
                    for value in values:
                        assert value.type == 0x6e736673, hex(value.type)
                        assert value.bsize == value.frsize == 4096
                        assert value.namelen == 255 and value.flags & 0x20
                        assert (value.blocks, value.bfree, value.bavail,
                                value.files, value.ffree) == (0, 0, 0, 0, 0)
                finally:
                    os.close(direct)
                    os.close(fd)
            subprocess.run(["df", "-P", target], check=True)
            checked(libc.umount2(os.fsencode(target), 0))
            mounted = False
            assert fetch(path=target).type == underlying.type
            missing = Statfs()
            assert libc.statfs(os.fsencode(target + ".missing"),
                               ctypes.byref(missing)) == -1
            assert ctypes.get_errno() == errno.ENOENT
        finally:
            if mounted:
                checked(libc.umount2(os.fsencode(target), 0))
    print("STATFS_NAMESPACE_PROBE_PASS")


if __name__ == "__main__":
    main()
