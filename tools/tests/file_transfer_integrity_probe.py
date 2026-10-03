#!/usr/bin/env python3
"""Check file transfer and vectored writes against deterministic block contents."""
import concurrent.futures
import hashlib
import os
import pathlib
import tempfile

DATA = b"".join(hashlib.sha256(str(block).encode()).digest() * 128
                for block in range(512))

def check(method):
    with tempfile.TemporaryDirectory(prefix=f"integrity-{method}-", dir=".") as directory:
        source = pathlib.Path(directory) / "source"
        target = pathlib.Path(directory) / "target"
        source.write_bytes(DATA)
        src = os.open(source, os.O_RDONLY)
        dst = os.open(target, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            done = 0
            while done < len(DATA):
                amount = min(65536, len(DATA) - done)
                if method == "writev":
                    count = os.writev(dst, [DATA[done:done + 17],
                                            DATA[done + 17:done + amount]])
                elif method == "sendfile":
                    count = os.sendfile(dst, src, done, amount)
                elif method == "copy_file_range":
                    count = os.copy_file_range(src, dst, amount)
                else:
                    pipe_r, pipe_w = os.pipe()
                    try:
                        count = os.splice(src, pipe_w, min(amount, 4096))
                        moved = 0
                        while moved < count:
                            step = os.splice(pipe_r, dst, count - moved)
                            assert step > 0, (method, "zero pipe transfer")
                            moved += step
                    finally:
                        os.close(pipe_r)
                        os.close(pipe_w)
                assert count > 0, (method, "zero transfer", done)
                done += count
            os.fsync(dst)
        finally:
            os.close(src)
            os.close(dst)
        actual = target.read_bytes()
        assert actual == DATA, (method, len(actual), hashlib.sha256(actual).hexdigest())
        print(f"PASS {method} bytes={len(actual)}", flush=True)

for mode in ("writev", "sendfile", "copy_file_range", "splice"):
    check(mode)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(check, ["writev", "sendfile", "copy_file_range", "splice"] * 2))
print("PASS sequential and concurrent file transfer integrity", flush=True)
