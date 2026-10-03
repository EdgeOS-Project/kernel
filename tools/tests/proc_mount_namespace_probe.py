#!/usr/bin/env python3
"""Compare inherited and freshly mounted proc PID views in a child namespace."""
import ctypes
import json
import os
import platform
import select
import signal
import tempfile

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
parent = os.getpid()
proc = os.open('/proc', os.O_PATH)
results = []
mountpoint = tempfile.mkdtemp(prefix='edgeos-proc-view-')
for iteration in range(2):
    rd, wr = os.pipe()
    flags = 0x20000000 | 0x20000 | signal.SIGCHLD
    if os.geteuid() != 0:
        flags |= 0x10000000
    child = libc.syscall(ctypes.c_long({'aarch64': 220, 'x86_64': 56}[platform.machine()]), ctypes.c_ulong(flags), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    if child < 0:
        raise OSError(ctypes.get_errno(), 'clone')
    if child == 0:
        os.close(rd)
        signal.alarm(12)
        checks = []
        def check(name, actual, expected):
            checks.append(dict(name=name, actual=actual, expected=expected, passed=actual == expected))
        def read_text(directory, name):
            fd = os.open(name, os.O_RDONLY, dir_fd=directory)
            with os.fdopen(fd) as stream:
                return stream.read()
        def check_thread_files(directory, prefix):
            check(prefix + '_thread_namespace', os.readlink('thread-self/ns/pid', dir_fd=directory), os.readlink('self/ns/pid', dir_fd=directory))
            check(prefix + '_thread_uid_map', read_text(directory, 'thread-self/uid_map'), read_text(directory, 'self/uid_map'))
        def status(directory, name):
            fd = os.open(name + '/status', os.O_RDONLY, dir_fd=directory)
            with os.fdopen(fd) as stream:
                return {line.split(':', 1)[0]: line.split(':', 1)[1].strip() for line in stream if ':' in line}
        try:
            outer = int(os.readlink('self', dir_fd=proc))
            check('namespace_getpid', os.getpid(), 1)
            check('inherited_self_is_outer_pid', outer > 1, True)
            check('inherited_thread_self', os.readlink('thread-self', dir_fd=proc), f'{outer}/task/{outer}')
            check('inherited_parent_visible', int(status(proc, str(parent))['Pid']), parent)
            check_thread_files(proc, 'inherited')
            check('inherited_self_status', int(status(proc, 'self')['Pid']), outer)
            check('inherited_numeric_status', int(status(proc, str(outer))['Pid']), outer)
            if libc.mount(b'proc', os.fsencode(mountpoint), b'proc', ctypes.c_ulong(0), None) != 0:
                raise OSError(ctypes.get_errno(), 'mount proc')
            fresh = os.open(mountpoint, os.O_PATH)
            check('fresh_self', os.readlink('self', dir_fd=fresh), '1')
            check('fresh_thread_self', os.readlink('thread-self', dir_fd=fresh), '1/task/1')
            check_thread_files(fresh, 'fresh')
            check('fresh_status_pid', int(status(fresh, 'self')['Pid']), 1)
            check('fresh_status_ppid', int(status(fresh, 'self')['PPid']), 0)
            check('fresh_numeric_status', int(status(fresh, '1')['Pid']), 1)
            check('inherited_unchanged_after_new_mount', int(os.readlink('self', dir_fd=proc)), outer)
            entries = os.listdir(mountpoint)
            check('fresh_directory_contains_init', '1' in entries, True)
            check('fresh_directory_hides_outer_pid', str(outer) in entries, False)
            os.close(fresh)
            if libc.umount2(os.fsencode(mountpoint), 0) != 0:
                raise OSError(ctypes.get_errno(), 'umount proc')
            check('inherited_unchanged_after_unmount', int(os.readlink('self', dir_fd=proc)), outer)
        except BaseException as error:
            checks.append(dict(name='exception', passed=False, error=repr(error)))
        os.write(wr, json.dumps(checks).encode())
        os._exit(0 if all(x['passed'] for x in checks) else 1)
    os.close(wr)
    try:
        if not select.select([rd], [], [], 15)[0]:
            os.kill(child, signal.SIGKILL)
            raise TimeoutError('Child probe deadline')
        checks = json.loads(os.read(rd, 16384))
    finally:
        _, statuscode = os.waitpid(child, 0)
        os.close(rd)
    results.append(dict(iteration=iteration, child=child, status=statuscode, checks=checks))
os.close(proc)
os.rmdir(mountpoint)
print(json.dumps(dict(architecture=platform.machine(), euid=os.geteuid(), results=results, passed=all(r['status'] == 0 for r in results)), indent=2))
