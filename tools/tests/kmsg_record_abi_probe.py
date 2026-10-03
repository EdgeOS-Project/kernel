#!/usr/bin/env python3
"""Verify /dev/kmsg record boundaries without clearing or suppressing logs."""
import ctypes
import errno
import os
import time


def main():
    token = f"edgeos-kmsg-probe-{os.getpid()}-{time.monotonic_ns()}".encode()
    reader = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
    writer = -1
    try:
        assert os.lseek(reader, 0, os.SEEK_END) == 0
        for origin in (os.SEEK_SET, os.SEEK_DATA, os.SEEK_END):
            assert os.lseek(reader, 0, origin) == 0
        for origin in (os.SEEK_CUR, os.SEEK_HOLE):
            try:
                os.lseek(reader, 0, origin)
            except OSError as error:
                assert error.errno == errno.EINVAL, error
            else:
                raise AssertionError("unsupported kmsg seek origin succeeded")
        for origin in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END,
                       os.SEEK_DATA, os.SEEK_HOLE):
            for offset in (-1, 1):
                try:
                    os.lseek(reader, offset, origin)
                except OSError as error:
                    assert error.errno == errno.ESPIPE, error
                else:
                    raise AssertionError("nonzero kmsg seek offset succeeded")
        writer = os.open("/dev/kmsg", os.O_WRONLY)
        fragments = [token, b": systemd-style ", b"error detail preserved", b"\n"]
        expected = b"".join(fragments)
        assert os.writev(writer, fragments) == len(expected)
        large = token + b": " + b"x" * 850 + b" END\n"
        assert len(large) <= 1024
        assert os.write(writer, large) == len(large)

        rejected = token + b": REJECTED " + b"z" * 1024
        try:
            os.write(writer, rejected)
        except OSError as error:
            assert error.errno == errno.EINVAL, error
        else:
            raise AssertionError("oversized kmsg write was not rejected")

        class Iovec(ctypes.Structure):
            _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]

        libc = ctypes.CDLL(None, use_errno=True)
        libc.writev.argtypes = [ctypes.c_int, ctypes.POINTER(Iovec), ctypes.c_int]
        libc.writev.restype = ctypes.c_ssize_t
        prefix = ctypes.create_string_buffer(token + b": FAULT_PREFIX")
        vectors = (Iovec * 2)(Iovec(ctypes.addressof(prefix), len(prefix.value)),
                              Iovec(1, 8))
        assert libc.writev(writer, vectors, 2) == -1
        assert ctypes.get_errno() == errno.EFAULT

        # This delimiter follows all tested writes; unrelated records remain intact.
        delimiter = token + b": COMPLETE\n"
        assert os.write(writer, delimiter) == len(delimiter)
        found = []
        complete = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                record = os.read(reader, 16384)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if not record:
                time.sleep(0.01)
                continue
            header, separator, body = record.partition(b";")
            assert separator and len(header.split(b",")) >= 4, record
            if token not in body:
                continue
            found.append(body)
            if body == delimiter:
                complete = True
                break
        assert complete, "completion record was not observed"
        assert found == [expected, large, delimiter], found
        print("KMSG_RECORD_ABI_PROBE_PASS")
    finally:
        if writer >= 0:
            os.close(writer)
        os.close(reader)


if __name__ == "__main__":
    main()
