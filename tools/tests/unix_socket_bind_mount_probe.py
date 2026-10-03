#!/usr/bin/env python3
"""Connect to a Unix socket through a bind mount after removing its original name."""
import ctypes
import os
import pathlib
import socket
import tempfile

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]
def checked(result, name):
    if result < 0: raise OSError(ctypes.get_errno(), name)

with tempfile.TemporaryDirectory(prefix="unix-bind-", dir=".") as directory:
    root = pathlib.Path(directory).resolve()
    source, alias = root / "server", root / "alias"
    alias.touch()
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(source))
    listener.listen(1)
    listener.settimeout(5)
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(ready_r)
        os.close(go_w)
        try:
            checked(libc.unshare(0x20000), "unshare")
            checked(libc.mount(None, b"/", None, 16384 | (1 << 18), None), "private mounts")
            checked(libc.mount(os.fsencode(source), os.fsencode(alias), None, 4096, None), "bind socket")
            os.write(ready_w, b"r")
            assert os.read(go_r, 1) == b"g"
            client = socket.socket(socket.AF_UNIX)
            client.settimeout(5)
            client.connect(str(alias))
            client.sendall(b"ping")
            assert client.recv(4) == b"pong"
            client.close()
            os._exit(0)
        except BaseException as error:
            print(f"FAIL child: {error}", flush=True)
            os._exit(1)
    os.close(ready_w)
    os.close(go_r)
    try:
        assert os.read(ready_r, 1) == b"r"
        source.unlink()
        os.write(go_w, b"g")
        connection, _ = listener.accept()
        assert connection.recv(4) == b"ping"
        connection.sendall(b"pong")
        connection.close()
    finally:
        os.close(ready_r)
        os.close(go_w)
        listener.close()
        result = os.waitpid(child, 0)[1]
    assert result == 0, result
print("PASS Unix socket bind mount and unlink", flush=True)
