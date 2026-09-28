#!/usr/bin/env python3
"""Exercise the TCP loopback path used by IDLE's local RPC server."""

import socket
import threading


def exercise(family: socket.AddressFamily, host: str) -> None:
    print(f"{family.name}_CREATE", flush=True)
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(f"{family.name}_BIND", flush=True)
    server.bind((host, 0))
    print(f"{family.name}_LISTEN", flush=True)
    server.listen(1)
    address = server.getsockname()
    received = []

    def client_main() -> None:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            print(f"{family.name}_CONNECT {address!r}", flush=True)
            client.connect(address)
            print(f"{family.name}_CONNECTED", flush=True)
            client.sendall(b"edgeos-idle-rpc")
            print(f"{family.name}_SENT", flush=True)
            received.append(client.recv(32))
            print(f"{family.name}_RECEIVED", flush=True)

    client_thread = threading.Thread(target=client_main)
    client_thread.start()
    print(f"{family.name}_ACCEPT", flush=True)
    connection, peer = server.accept()
    print(f"{family.name}_ACCEPTED {peer!r}", flush=True)
    with connection:
        payload = connection.recv(32)
        connection.sendall(payload.upper())
    client_thread.join(10)
    server.close()
    if client_thread.is_alive():
        raise RuntimeError(f"{family.name} client did not complete")
    if received != [b"EDGEOS-IDLE-RPC"]:
        raise RuntimeError(f"{family.name} payload mismatch: {received!r}")
    print(f"{family.name}_PASS listen={address!r} peer={peer!r}")


def main() -> None:
    exercise(socket.AF_INET, "127.0.0.1")
    if socket.has_ipv6:
        exercise(socket.AF_INET6, "::1")
    print("PYTHON_LOOPBACK_SOCKET_PROBE_PASS")


if __name__ == "__main__":
    main()
