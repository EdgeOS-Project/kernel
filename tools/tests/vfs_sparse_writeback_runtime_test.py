#!/usr/bin/env python3
"""Exercise sparse seeking and persistent shared mappings on a real rootfs."""

import ctypes
import fcntl
import mmap
import os
import struct
from pathlib import Path


PAGE_SIZE = 4096
TEST_PATH = Path("/var/tmp/edgeos-vfs-sparse-writeback")
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_FLAG_SYNC = 0x00000001
FIEMAP_EXTENT_LAST = 0x00000001
FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02
FALLOC_FL_COLLAPSE_RANGE = 0x08
FALLOC_FL_INSERT_RANGE = 0x20


def fallocate(fd: int, mode: int, offset: int, length: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.fallocate(
        ctypes.c_int(fd), ctypes.c_int(mode),
        ctypes.c_longlong(offset), ctypes.c_longlong(length),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def main() -> None:
    try:
        TEST_PATH.unlink()
    except FileNotFoundError:
        pass

    fd = os.open(TEST_PATH, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
    mapping = None
    try:
        os.ftruncate(fd, 16 * PAGE_SIZE)
        os.pwrite(fd, b"A" * PAGE_SIZE, 0)
        os.pwrite(fd, b"B" * PAGE_SIZE, 8 * PAGE_SIZE)
        os.fsync(fd)

        extents = (
            os.lseek(fd, 0, os.SEEK_DATA),
            os.lseek(fd, 0, os.SEEK_HOLE),
            os.lseek(fd, PAGE_SIZE, os.SEEK_DATA),
            os.lseek(fd, 8 * PAGE_SIZE, os.SEEK_HOLE),
        )
        expected = (0, PAGE_SIZE, 8 * PAGE_SIZE, 9 * PAGE_SIZE)
        if extents != expected:
            raise AssertionError(f"sparse extent mismatch: {extents} != {expected}")

        fiemap = bytearray(32 + 4 * 56)
        struct.pack_into(
            "<QQIIII", fiemap, 0,
            0, (1 << 64) - 1, FIEMAP_FLAG_SYNC, 0, 4, 0,
        )
        fcntl.ioctl(fd, FS_IOC_FIEMAP, fiemap, True)
        _, _, _, mapped_extents, _, _ = struct.unpack_from(
            "<QQIIII", fiemap, 0
        )
        if mapped_extents != 2:
            raise AssertionError(
                f"fiemap extent count mismatch: {mapped_extents} != 2"
            )
        first = struct.unpack_from("<QQQQQIIII", fiemap, 32)
        second = struct.unpack_from("<QQQQQIIII", fiemap, 32 + 56)
        if first[0] != 0 or first[2] != PAGE_SIZE:
            raise AssertionError(f"unexpected first fiemap extent: {first}")
        if second[0] != 8 * PAGE_SIZE or second[2] != PAGE_SIZE:
            raise AssertionError(f"unexpected second fiemap extent: {second}")
        if not second[5] & FIEMAP_EXTENT_LAST:
            raise AssertionError("final fiemap extent is missing LAST")

        mapping = mmap.mmap(fd, 16 * PAGE_SIZE, access=mmap.ACCESS_WRITE)
        try:
            mapping[PAGE_SIZE : 2 * PAGE_SIZE] = b"C" * PAGE_SIZE
            mapping.flush(PAGE_SIZE, PAGE_SIZE)
            os.fsync(fd)
        finally:
            mapping.close()
            mapping = None
    finally:
        os.close(fd)

    fd = os.open(TEST_PATH, os.O_RDONLY)
    try:
        if os.pread(fd, PAGE_SIZE, PAGE_SIZE) != b"C" * PAGE_SIZE:
            raise AssertionError("shared mapping was not persisted")
    finally:
        os.close(fd)
        TEST_PATH.unlink(missing_ok=True)

    fd = os.open(TEST_PATH, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
    try:
        truncate_original = (
            b"A" * PAGE_SIZE + b"B" * PAGE_SIZE + b"C" * PAGE_SIZE
        )
        if os.write(fd, truncate_original) != len(truncate_original):
            raise AssertionError("short truncate fixture write")
        os.fsync(fd)
        mapping = mmap.mmap(fd, len(truncate_original), access=mmap.ACCESS_WRITE)
        if mapping[:] != truncate_original:
            raise AssertionError("truncate mapping fixture mismatch")
        truncated_length = PAGE_SIZE + PAGE_SIZE // 2
        os.ftruncate(fd, truncated_length)
        expected_truncated = truncate_original[:truncated_length]
        if os.pread(fd, truncated_length, 0) != expected_truncated:
            raise AssertionError("truncate shrink changed retained data")
        if mapping[:truncated_length] != expected_truncated:
            raise AssertionError("truncate shrink left stale mapped data")
        os.ftruncate(fd, len(truncate_original))
        extended = mapping[truncated_length:len(truncate_original)]
        if extended != b"\0" * (len(truncate_original) - truncated_length):
            raise AssertionError("truncate extension did not expose zeroes")
    finally:
        if mapping is not None:
            mapping.close()
            mapping = None
        os.close(fd)
        TEST_PATH.unlink(missing_ok=True)

    fd = os.open(TEST_PATH, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
    try:
        original = b"".join(
            bytes([ord("A") + index]) * PAGE_SIZE
            for index in range(5)
        )
        if os.write(fd, original) != len(original):
            raise AssertionError("short fallocate fixture write")
        os.fsync(fd)
        mapping = mmap.mmap(fd, len(original), access=mmap.ACCESS_WRITE)
        if mapping[:] != original:
            raise AssertionError("fallocate mapping fixture mismatch")

        fallocate(
            fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            PAGE_SIZE, PAGE_SIZE,
        )
        if os.pread(fd, PAGE_SIZE, PAGE_SIZE) != b"\0" * PAGE_SIZE:
            raise AssertionError("punch-hole did not expose zeroes")
        if mapping[PAGE_SIZE:2 * PAGE_SIZE] != b"\0" * PAGE_SIZE:
            raise AssertionError("punch-hole left stale mapped data")
        if os.lseek(fd, PAGE_SIZE, os.SEEK_DATA) != 2 * PAGE_SIZE:
            raise AssertionError("punch-hole retained a mapped data block")

        fallocate(fd, FALLOC_FL_COLLAPSE_RANGE, PAGE_SIZE, PAGE_SIZE)
        if os.fstat(fd).st_size != 4 * PAGE_SIZE:
            raise AssertionError("collapse-range produced the wrong size")
        collapsed = os.pread(fd, 4 * PAGE_SIZE, 0)
        expected_collapsed = b"".join(
            value * PAGE_SIZE for value in (b"A", b"C", b"D", b"E")
        )
        if collapsed != expected_collapsed:
            raise AssertionError("collapse-range moved incorrect data")
        if mapping[:4 * PAGE_SIZE] != expected_collapsed:
            raise AssertionError("collapse-range left stale mapped data")

        fallocate(fd, FALLOC_FL_INSERT_RANGE, 2 * PAGE_SIZE, PAGE_SIZE)
        if os.fstat(fd).st_size != 5 * PAGE_SIZE:
            raise AssertionError("insert-range produced the wrong size")
        inserted = os.pread(fd, 5 * PAGE_SIZE, 0)
        expected_inserted = (
            b"A" * PAGE_SIZE + b"C" * PAGE_SIZE +
            b"\0" * PAGE_SIZE + b"D" * PAGE_SIZE + b"E" * PAGE_SIZE
        )
        if inserted != expected_inserted:
            raise AssertionError("insert-range moved incorrect data")
        if mapping[:5 * PAGE_SIZE] != expected_inserted:
            raise AssertionError("insert-range left stale mapped data")
        if os.lseek(fd, 2 * PAGE_SIZE, os.SEEK_DATA) != 3 * PAGE_SIZE:
            raise AssertionError("insert-range did not create a sparse hole")
        os.fsync(fd)
    finally:
        if mapping is not None:
            mapping.close()
        os.close(fd)
        TEST_PATH.unlink(missing_ok=True)

    print(
        "VFS_SPARSE_WRITEBACK_RUNTIME_PASS "
        f"extents={extents} fiemap_extents={mapped_extents} "
        "truncate=shrink,extend fallocate_modes=punch,collapse,insert"
    )


if __name__ == "__main__":
    main()
