#!/usr/bin/env python3
"""Exercise EdgeOS FUSE through a real mount and an in-memory daemon."""

import ctypes
import errno
import os
import stat
import struct
import subprocess
import sys
import time
import traceback


FUSE_LOOKUP = 1
FUSE_GETATTR = 3
FUSE_SETATTR = 4
FUSE_READLINK = 5
FUSE_SYMLINK = 6
FUSE_MKNOD = 8
FUSE_MKDIR = 9
FUSE_UNLINK = 10
FUSE_RMDIR = 11
FUSE_RENAME = 12
FUSE_LINK = 13
FUSE_OPEN = 14
FUSE_READ = 15
FUSE_WRITE = 16
FUSE_STATFS = 17
FUSE_RELEASE = 18
FUSE_FSYNC = 20
FUSE_SETXATTR = 21
FUSE_GETXATTR = 22
FUSE_LISTXATTR = 23
FUSE_REMOVEXATTR = 24
FUSE_FLUSH = 25
FUSE_INIT = 26
FUSE_OPENDIR = 27
FUSE_READDIR = 28
FUSE_RELEASEDIR = 29
FUSE_FSYNCDIR = 30
FUSE_ACCESS = 34
FUSE_CREATE = 35
FUSE_DESTROY = 38
FUSE_FALLOCATE = 43
FUSE_NOTIFY_INVAL_ENTRY = 3
RESULT_PATH = "/var/tmp/edgeos-fuse-runtime-result"

FUSE_SET_ATTR_MODE = 1 << 0
FUSE_SET_ATTR_UID = 1 << 1
FUSE_SET_ATTR_GID = 1 << 2
FUSE_SET_ATTR_SIZE = 1 << 3
FUSE_SET_ATTR_ATIME = 1 << 4
FUSE_SET_ATTR_MTIME = 1 << 5

HEADER_IN = struct.Struct("<IIQQIIII")
HEADER_OUT = struct.Struct("<IiQ")
ATTR = struct.Struct("<QQQQQQIIIIIIIIII")
ENTRY_PREFIX = struct.Struct("<QQQQII")
ATTR_OUT_PREFIX = struct.Struct("<QII")
READ_WRITE_IN = struct.Struct("<QQIIQII")


def split_strings(payload):
    return [part.decode() for part in payload.split(b"\0") if part]


def record_result(lines):
    with open(RESULT_PATH, "w", encoding="utf-8") as result_file:
        result_file.write("\n".join(lines) + "\n")
        result_file.flush()
        os.fsync(result_file.fileno())


class Node:
    def __init__(self, nodeid, parent, name, mode, data=b"", target=b""):
        self.nodeid = nodeid
        self.parent = parent
        self.name = name
        self.mode = mode
        self.data = bytearray(data)
        self.target = target
        self.children = {}
        self.xattrs = {}
        self.nlink = 2 if stat.S_ISDIR(mode) else 1
        self.uid = 0
        self.gid = 0
        self.atime = 1_700_000_000
        self.mtime = 1_700_000_000
        self.ctime = 1_700_000_000


class MemoryFuse:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.next_nodeid = 2
        self.nodes = {1: Node(1, 1, "", stat.S_IFDIR | 0o755)}
        self.add_node(1, "hello.txt", stat.S_IFREG | 0o644,
                      b"hello-from-edgeos-fuse\n")

    def add_node(self, parent, name, mode, data=b"", target=b""):
        if name in self.nodes[parent].children:
            raise FileExistsError(name)
        nodeid = self.next_nodeid
        self.next_nodeid += 1
        node = Node(nodeid, parent, name, mode, data, target)
        self.nodes[nodeid] = node
        self.nodes[parent].children[name] = nodeid
        return node

    def attr(self, node):
        size = len(node.target) if stat.S_ISLNK(node.mode) else len(node.data)
        return ATTR.pack(
            node.nodeid, size, (size + 511) // 512,
            node.atime, node.mtime, node.ctime,
            0, 0, 0, node.mode, node.nlink, node.uid, node.gid,
            0, 4096, 0)

    def entry(self, node):
        return ENTRY_PREFIX.pack(node.nodeid, 1, 0, 0, 0, 0) + self.attr(node)

    def attr_out(self, node):
        return ATTR_OUT_PREFIX.pack(0, 0, 0) + self.attr(node)

    def reply(self, unique, payload=b"", error=0):
        message = HEADER_OUT.pack(HEADER_OUT.size + len(payload), error, unique)
        os.write(self.descriptor, message + payload)

    def lookup(self, parent, name):
        if name == ".":
            return self.nodes[parent]
        if name == "..":
            return self.nodes[self.nodes[parent].parent]
        nodeid = self.nodes[parent].children.get(name)
        return self.nodes.get(nodeid)

    def remove(self, parent, name, directory):
        node = self.lookup(parent, name)
        if node is None:
            return -errno.ENOENT
        if directory and not stat.S_ISDIR(node.mode):
            return -errno.ENOTDIR
        if not directory and stat.S_ISDIR(node.mode):
            return -errno.EISDIR
        if directory and node.children:
            return -errno.ENOTEMPTY
        del self.nodes[parent].children[name]
        if node.nlink > 1:
            node.nlink -= 1
        else:
            self.nodes.pop(node.nodeid, None)
        return 0

    def dispatch(self, message):
        if len(message) < HEADER_IN.size:
            raise RuntimeError("short FUSE request header")
        length, opcode, unique, nodeid, _uid, _gid, _pid, _padding = \
            HEADER_IN.unpack_from(message)
        if length != len(message):
            raise RuntimeError("incorrect FUSE request length")
        payload = message[HEADER_IN.size:]

        if opcode == FUSE_INIT:
            major, minor, max_readahead, flags = struct.unpack_from("<IIII", payload)
            if major != 7 or minor < 23:
                self.reply(unique, error=-errno.EPROTO)
                return True
            supported = flags & ((1 << 0) | (1 << 3) | (1 << 5) |
                                 (1 << 12) | (1 << 15) | (1 << 22))
            init_out = struct.pack(
                "<IIIIHHIIHHI7I", 7, min(minor, 31), max_readahead,
                supported, 16, 12, 65536, 1, 16, 0, 0,
                0, 0, 0, 0, 0, 0, 0)
            self.reply(unique, init_out)
            invalidated_name = b"hello.txt"
            notification = struct.pack(
                "<QII", 1, len(invalidated_name), 0) + invalidated_name
            self.reply(0, notification, FUSE_NOTIFY_INVAL_ENTRY)
            return True

        node = self.nodes.get(nodeid)
        if node is None:
            self.reply(unique, error=-errno.ENOENT)
            return True

        if opcode == FUSE_LOOKUP:
            found = self.lookup(nodeid, split_strings(payload)[0])
            self.reply(unique, self.entry(found) if found else b"",
                       0 if found else -errno.ENOENT)
        elif opcode == FUSE_GETATTR:
            self.reply(unique, self.attr_out(node))
        elif opcode == FUSE_SETATTR:
            fields = struct.unpack_from("<IIQQQQQQIIIIIIII", payload)
            valid = fields[0]
            if valid & FUSE_SET_ATTR_SIZE:
                size = fields[3]
                node.data = node.data[:size] + b"\0" * max(0, size - len(node.data))
            if valid & FUSE_SET_ATTR_ATIME:
                node.atime = fields[5]
            if valid & FUSE_SET_ATTR_MTIME:
                node.mtime = fields[6]
            if valid & FUSE_SET_ATTR_MODE:
                node.mode = stat.S_IFMT(node.mode) | (fields[11] & 0o7777)
            if valid & FUSE_SET_ATTR_UID:
                node.uid = fields[13]
            if valid & FUSE_SET_ATTR_GID:
                node.gid = fields[14]
            self.reply(unique, self.attr_out(node))
        elif opcode in (FUSE_OPEN, FUSE_OPENDIR):
            self.reply(unique, struct.pack("<QII", node.nodeid, 0, 0))
        elif opcode == FUSE_READ:
            _fh, offset, size, _read_flags, _owner, _flags, _padding = \
                READ_WRITE_IN.unpack_from(payload)
            self.reply(unique, bytes(node.data[offset:offset + size]))
        elif opcode == FUSE_WRITE:
            _fh, offset, size, _write_flags, _owner, _flags, _padding = \
                READ_WRITE_IN.unpack_from(payload)
            data = payload[READ_WRITE_IN.size:READ_WRITE_IN.size + size]
            if len(node.data) < offset:
                node.data.extend(b"\0" * (offset - len(node.data)))
            end = offset + len(data)
            if len(node.data) < end:
                node.data.extend(b"\0" * (end - len(node.data)))
            node.data[offset:end] = data
            self.reply(unique, struct.pack("<II", len(data), 0))
        elif opcode == FUSE_CREATE:
            _flags, mode, _umask, _open_flags = struct.unpack_from("<IIII", payload)
            name = split_strings(payload[16:])[0]
            if name in node.children:
                self.reply(unique, error=-errno.EEXIST)
            else:
                created = self.add_node(nodeid, name, mode)
                self.reply(unique, self.entry(created) +
                           struct.pack("<QII", created.nodeid, 0, 0))
        elif opcode in (FUSE_MKDIR, FUSE_MKNOD):
            if opcode == FUSE_MKDIR:
                mode, _umask = struct.unpack_from("<II", payload)
                names = split_strings(payload[8:])
            else:
                mode, _rdev, _umask, _padding = struct.unpack_from("<IIII", payload)
                names = split_strings(payload[16:])
            if names[0] in node.children:
                self.reply(unique, error=-errno.EEXIST)
            else:
                created = self.add_node(nodeid, names[0], mode)
                self.reply(unique, self.entry(created))
        elif opcode == FUSE_SYMLINK:
            name, target = split_strings(payload)[:2]
            created = self.add_node(nodeid, name, stat.S_IFLNK | 0o777,
                                    target=target.encode())
            self.reply(unique, self.entry(created))
        elif opcode == FUSE_READLINK:
            self.reply(unique, node.target)
        elif opcode in (FUSE_UNLINK, FUSE_RMDIR):
            name = split_strings(payload)[0]
            result = self.remove(nodeid, name, opcode == FUSE_RMDIR)
            self.reply(unique, error=result)
        elif opcode == FUSE_RENAME:
            new_parent = struct.unpack_from("<Q", payload)[0]
            old_name, new_name = split_strings(payload[8:])[:2]
            moved = self.lookup(nodeid, old_name)
            if moved is None:
                self.reply(unique, error=-errno.ENOENT)
            elif new_name in self.nodes[new_parent].children:
                self.reply(unique, error=-errno.EEXIST)
            else:
                del node.children[old_name]
                self.nodes[new_parent].children[new_name] = moved.nodeid
                moved.parent = new_parent
                moved.name = new_name
                self.reply(unique)
        elif opcode == FUSE_LINK:
            old_nodeid = struct.unpack_from("<Q", payload)[0]
            name = split_strings(payload[8:])[0]
            linked = self.nodes.get(old_nodeid)
            if linked is None:
                self.reply(unique, error=-errno.ENOENT)
            else:
                node.children[name] = linked.nodeid
                linked.nlink += 1
                self.reply(unique, self.entry(linked))
        elif opcode == FUSE_READDIR:
            _fh, offset, size, _read_flags, _owner, _flags, _padding = \
                READ_WRITE_IN.unpack_from(payload)
            records = bytearray()
            names = sorted(node.children)
            for position, name in enumerate(names[int(offset):], int(offset) + 1):
                child = self.nodes[node.children[name]]
                encoded = name.encode()
                record = struct.pack("<QQII", child.nodeid, position,
                                     len(encoded), (child.mode >> 12) & 15) + encoded
                record += b"\0" * ((-len(record)) & 7)
                if len(records) + len(record) > size:
                    break
                records.extend(record)
            self.reply(unique, bytes(records))
        elif opcode == FUSE_STATFS:
            self.reply(unique, struct.pack(
                "<QQQQQ10I", 262144, 196608, 196608, 65536, 60000,
                4096, 255, 4096, 0, 0, 0, 0, 0, 0, 0))
        elif opcode == FUSE_SETXATTR:
            size, _flags, _set_flags, _padding = struct.unpack_from("<IIII", payload)
            raw = payload[16:]
            name_end = raw.index(0)
            name = raw[:name_end].decode()
            node.xattrs[name] = bytes(raw[name_end + 1:name_end + 1 + size])
            self.reply(unique)
        elif opcode in (FUSE_GETXATTR, FUSE_LISTXATTR):
            size, _padding = struct.unpack_from("<II", payload)
            if opcode == FUSE_GETXATTR:
                name = split_strings(payload[8:])[0]
                value = node.xattrs.get(name)
                if value is None:
                    self.reply(unique, error=-errno.ENODATA)
                    return True
            else:
                value = b"".join(name.encode() + b"\0" for name in sorted(node.xattrs))
            if size == 0:
                self.reply(unique, struct.pack("<II", len(value), 0))
            elif size < len(value):
                self.reply(unique, error=-errno.ERANGE)
            else:
                self.reply(unique, value)
        elif opcode == FUSE_REMOVEXATTR:
            name = split_strings(payload)[0]
            if name not in node.xattrs:
                self.reply(unique, error=-errno.ENODATA)
            else:
                del node.xattrs[name]
                self.reply(unique)
        elif opcode == FUSE_FALLOCATE:
            _fh, offset, requested, _mode, _padding = struct.unpack_from("<QQQII", payload)
            end = offset + requested
            if len(node.data) < end:
                node.data.extend(b"\0" * (end - len(node.data)))
            self.reply(unique)
        elif opcode in (FUSE_RELEASE, FUSE_RELEASEDIR, FUSE_FLUSH,
                        FUSE_FSYNC, FUSE_FSYNCDIR, FUSE_ACCESS):
            self.reply(unique)
        elif opcode == FUSE_DESTROY:
            self.reply(unique)
            return False
        else:
            self.reply(unique, error=-errno.ENOSYS)
        return True

    def run(self, stop_event=None):
        while True:
            try:
                message = os.read(self.descriptor, 69632)
            except BlockingIOError:
                if stop_event is not None and stop_event.is_set():
                    return
                continue
            if not message:
                return
            if not self.dispatch(message):
                return


def mount_fuse(descriptor, mountpoint):
    libc = ctypes.CDLL(None, use_errno=True)
    options = f"fd={descriptor},rootmode=40000,user_id=0,group_id=0".encode()
    result = libc.mount(b"edge-memory", mountpoint.encode(),
                        b"fuse.edge-memory", 0, options)
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def unmount_fuse(mountpoint):
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.umount2(mountpoint.encode(), 0)
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def main():
    try:
        os.unlink(RESULT_PATH)
    except FileNotFoundError:
        pass
    markers = ["FUSE_RUNTIME_NOTIFY_OK"]
    mountpoint = "/mnt/edgeos-fuse-runtime"
    os.makedirs(mountpoint, exist_ok=True)
    descriptor = os.open("/dev/fuse", os.O_RDWR)
    ready_reader, ready_writer = os.pipe()
    daemon_command = [
        sys.executable, __file__, "--daemon-fd", str(descriptor),
        "--ready-fd", str(ready_writer)]
    daemon = subprocess.Popen(
        daemon_command,
        pass_fds=(descriptor, ready_writer))
    os.close(ready_writer)
    if os.read(ready_reader, 1) != b"1":
        raise RuntimeError("FUSE daemon did not become ready")
    os.close(ready_reader)
    time.sleep(0.05)
    try:
        mount_fuse(descriptor, mountpoint)
    except BaseException:
        daemon.terminate()
        daemon.wait(5)
        os.close(descriptor)
        raise
    markers.append("FUSE_RUNTIME_MOUNTED")
    try:
        hello = os.path.join(mountpoint, "hello.txt")
        with open(hello, "rb") as source:
            assert source.read() == b"hello-from-edgeos-fuse\n"
        assert "hello.txt" in os.listdir(mountpoint)
        markers.append("FUSE_RUNTIME_READDIR_READ_OK")

        document = os.path.join(mountpoint, "document.txt")
        with open(document, "wb") as destination:
            destination.write(b"shared-fuse-write")
            destination.flush()
            os.fsync(destination.fileno())
        with open(document, "rb") as source:
            assert source.read() == b"shared-fuse-write"
        os.truncate(document, 6)
        with open(document, "rb") as source:
            assert source.read() == b"shared"
        markers.append("FUSE_RUNTIME_CREATE_WRITE_SYNC_TRUNCATE_OK")

        directory = os.path.join(mountpoint, "directory")
        os.mkdir(directory, 0o750)
        renamed = os.path.join(directory, "renamed.txt")
        os.rename(document, renamed)
        hardlink = os.path.join(mountpoint, "hardlink.txt")
        os.link(renamed, hardlink)
        symlink = os.path.join(mountpoint, "symlink.txt")
        os.symlink("directory/renamed.txt", symlink)
        assert os.readlink(symlink) == "directory/renamed.txt"
        with open(hardlink, "rb") as source:
            assert source.read() == b"shared"
        markers.append("FUSE_RUNTIME_NAMESPACE_LINKS_OK")

        if hasattr(os, "setxattr"):
            os.setxattr(renamed, "user.edgeos", b"fuse-xattr")
            assert os.getxattr(renamed, "user.edgeos") == b"fuse-xattr"
            assert "user.edgeos" in os.listxattr(renamed)
            os.removexattr(renamed, "user.edgeos")
            markers.append("FUSE_RUNTIME_XATTR_OK")

        statistics = os.statvfs(mountpoint)
        assert statistics.f_bsize == 4096
        markers.append("FUSE_RUNTIME_STATFS_OK")

        bulk_directory = os.path.join(mountpoint, "bulk")
        os.mkdir(bulk_directory)
        bulk_count = 1100
        for index in range(bulk_count):
            path = os.path.join(bulk_directory, f"node-{index:04d}")
            opened = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(opened)
        os.stat(os.path.join(
            bulk_directory, f"node-{bulk_count - 1:04d}"))
        markers.append(f"FUSE_RUNTIME_DYNAMIC_NODES_OK={bulk_count}")

        os.unlink(symlink)
        os.unlink(hardlink)
        os.unlink(renamed)
        os.rmdir(directory)
        markers.append("FUSE_RUNTIME_MUTATION_OK")
        markers.append("FUSE_RUNTIME_PASS")
    finally:
        try:
            unmount_fuse(mountpoint)
        finally:
            daemon.terminate()
            try:
                daemon.wait(5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
                raise RuntimeError("FUSE daemon did not stop")
            if daemon.returncode not in (0, -15):
                raise RuntimeError(
                    f"FUSE daemon failed with status {daemon.returncode}")
            os.close(descriptor)
    record_result(markers)
    print("\n".join(markers), flush=True)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "--daemon-fd" and \
                sys.argv[3] == "--ready-fd":
            daemon_descriptor = int(sys.argv[2])
            ready_descriptor = int(sys.argv[4])
            daemon_instance = MemoryFuse(daemon_descriptor)
            os.write(ready_descriptor, b"1")
            os.close(ready_descriptor)
            daemon_instance.run()
        else:
            main()
    except BaseException as exception:
        traceback.print_exc()
        failure = f"FUSE_RUNTIME_FAIL={exception!r}"
        try:
            record_result([failure, traceback.format_exc()])
        except BaseException:
            pass
        print(failure, flush=True)
        sys.exit(1)
