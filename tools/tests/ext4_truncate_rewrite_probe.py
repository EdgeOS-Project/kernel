#!/usr/bin/env python3
"""Verify that truncating an indexed extent tree leaves a writable file."""

import os
import sys
import tempfile


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    payload = b"extent-rewrite-ok\n"
    with tempfile.TemporaryFile(dir=directory) as stream:
        descriptor = stream.fileno()
        for iteration in range(3):
            # Logical gaps prevent the six extents from merging inline.
            for index in range(6):
                assert os.pwrite(descriptor, b"x", index * 8192) == 1
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            written = os.write(descriptor, payload)
            assert written == len(payload), (iteration, written, len(payload))
            assert os.pread(descriptor, len(payload), 0) == payload
            os.fsync(descriptor)
        print("EXT4_TRUNCATE_REWRITE_PASS", flush=True)


if __name__ == "__main__":
    main()
