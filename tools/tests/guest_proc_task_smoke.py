#!/usr/bin/env python3
"""Runtime validation for Linux procfs and cgroup task enumeration."""

import os
import signal
import sys
import threading
import time


class ProbeFailure(RuntimeError):
    pass


def expect(condition, message):
    if not condition:
        raise ProbeFailure(message)


def read_status(pid):
    fields = {}
    with open(f"/proc/{pid}/status", "r", encoding="ascii") as status_file:
        for line in status_file:
            name, separator, value = line.partition(":")
            if separator:
                fields[name] = value.strip()
    return fields


def numeric_directory_entries(path):
    return {int(name) for name in os.listdir(path) if name.isdigit()}


def numeric_file_entries(path):
    with open(path, "r", encoding="ascii") as entries_file:
        return {int(line) for line in entries_file if line.strip()}


def first_integer(fields, name):
    expect(name in fields, f"missing {name} in proc status")
    return int(fields[name].split()[0])


def current_cgroup_directory():
    with open("/proc/self/cgroup", "r", encoding="ascii") as cgroup_file:
        for line in cgroup_file:
            hierarchy, controllers, path = line.rstrip("\n").split(":", 2)
            if hierarchy == "0" and not controllers:
                return os.path.join("/sys/fs/cgroup", path.lstrip("/"))
    raise ProbeFailure("unified cgroup membership is unavailable")


def validate_identity(pid, expected_ppid=None):
    fields = read_status(pid)
    expect(first_integer(fields, "Pid") == pid, "Pid does not match")
    expect(first_integer(fields, "Tgid") == pid, "leader Tgid does not match")
    if expected_ppid is not None:
        expect(first_integer(fields, "PPid") == expected_ppid,
               "PPid does not match")
    expect(fields.get("State", "")[:1] in "RSTZ",
           "invalid Linux task state")


def validate_threads(pid):
    release = threading.Event()
    ready = threading.Barrier(3)
    native_ids = []

    def worker():
        native_ids.append(threading.get_native_id())
        ready.wait()
        release.wait(10)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    try:
        ready.wait(timeout=10)
        task_ids = numeric_directory_entries(f"/proc/{pid}/task")
        expected_ids = {pid, *native_ids}
        expect(expected_ids <= task_ids,
               f"missing task IDs: expected {expected_ids}, found {task_ids}")
        fields = read_status(pid)
        expect(first_integer(fields, "Threads") >= 3,
               "proc status thread count is too small")
        for tid in expected_ids:
            thread_fields = read_status(tid)
            expect(first_integer(thread_fields, "Tgid") == pid,
                   f"thread {tid} has the wrong Tgid")

        cgroup_threads_path = os.path.join(current_cgroup_directory(),
                                           "cgroup.threads")
        expect(os.path.exists(cgroup_threads_path),
               "cgroup v2 task interface is not mounted")
        cgroup_threads = numeric_file_entries(cgroup_threads_path)
        expect(expected_ids <= cgroup_threads,
               "cgroup.threads omitted a live thread")
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=10)
            expect(not thread.is_alive(), "worker thread did not exit")

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        task_ids = numeric_directory_entries(f"/proc/{pid}/task")
        if not expected_ids.intersection(task_ids - {pid}):
            break
        time.sleep(0.01)
    task_ids = numeric_directory_entries(f"/proc/{pid}/task")
    expect(not expected_ids.intersection(task_ids - {pid}),
           f"exited task IDs remain visible: {task_ids}")
    task_links = os.stat(f"/proc/{pid}/task").st_nlink
    expect(task_links == 2 + len(task_ids),
           f"task directory link count {task_links} does not match {task_ids}")


def validate_fork(parent_pid):
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        try:
            validate_identity(os.getpid(), parent_pid)
            os.write(write_fd, b"P")
            os._exit(0)
        except BaseException as error:
            os.write(write_fd, ("F" + str(error)).encode("ascii", "replace"))
            os._exit(1)

    os.close(write_fd)
    try:
        child_result = os.read(read_fd, 4096)
    finally:
        os.close(read_fd)
    waited_pid, status = os.waitpid(child_pid, 0)
    expect(waited_pid == child_pid, "waitpid returned the wrong child")
    expect(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
           f"child validation failed: {child_result!r}")
    expect(child_result == b"P", f"unexpected child result: {child_result!r}")


def validate_cgroup_migration():
    parent_cgroup = current_cgroup_directory()
    child_cgroup = os.path.join(parent_cgroup,
                                f"edgeos-proc-probe-{os.getpid()}")
    identity_read, identity_write = os.pipe()
    release_read, release_write = os.pipe()
    child_pid = -1
    os.mkdir(child_cgroup)
    try:
        child_pid = os.fork()
        if child_pid == 0:
            os.close(identity_read)
            os.close(release_write)
            release = threading.Event()
            ready = threading.Event()
            worker_tid = []

            def worker():
                worker_tid.append(threading.get_native_id())
                ready.set()
                release.wait(10)

            thread = threading.Thread(target=worker)
            thread.start()
            ready.wait(10)
            os.write(identity_write,
                     f"{os.getpid()} {worker_tid[0]}\n".encode("ascii"))
            os.read(release_read, 1)
            release.set()
            thread.join(10)
            os._exit(0 if not thread.is_alive() else 1)

        os.close(identity_write)
        identity_write = -1
        os.close(release_read)
        release_read = -1
        identity = os.read(identity_read, 128).decode("ascii").split()
        expect(len(identity) == 2, "child thread identity was not reported")
        leader_tid, worker_tid = map(int, identity)
        expect(leader_tid == child_pid, "child reported the wrong leader TID")

        with open(os.path.join(child_cgroup, "cgroup.procs"),
                  "w", encoding="ascii") as process_file:
            process_file.write(f"{child_pid}\n")
        expect(child_pid in numeric_file_entries(
                   os.path.join(child_cgroup, "cgroup.procs")),
               "child leader did not enter the target cgroup")
        expect({leader_tid, worker_tid} <= numeric_file_entries(
                   os.path.join(child_cgroup, "cgroup.threads")),
               "cgroup.procs did not migrate the full thread group")

        with open(os.path.join(parent_cgroup, "cgroup.procs"),
                  "w", encoding="ascii") as process_file:
            process_file.write(f"{child_pid}\n")
        expect(child_pid not in numeric_file_entries(
                   os.path.join(child_cgroup, "cgroup.procs")),
               "child leader did not return to the parent cgroup")
        os.write(release_write, b"R")
        os.close(release_write)
        release_write = -1
        waited_pid, status = os.waitpid(child_pid, 0)
        expect(waited_pid == child_pid and os.WIFEXITED(status) and
               os.WEXITSTATUS(status) == 0,
               "multithreaded cgroup child did not exit cleanly")
        child_pid = -1
    finally:
        for descriptor in (identity_read, identity_write,
                           release_read, release_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if child_pid > 0:
            try:
                with open(os.path.join(parent_cgroup, "cgroup.procs"),
                          "w", encoding="ascii") as process_file:
                    process_file.write(f"{child_pid}\n")
            except OSError:
                pass
            try:
                os.kill(child_pid, signal.SIGKILL)
                os.waitpid(child_pid, 0)
            except OSError:
                pass
        os.rmdir(child_cgroup)


def main():
    pid = os.getpid()
    validate_identity(pid, os.getppid())
    validate_threads(pid)
    validate_fork(pid)
    validate_cgroup_migration()

    cgroup_process_path = os.path.join(current_cgroup_directory(),
                                       "cgroup.procs")
    cgroup_processes = numeric_file_entries(cgroup_process_path)
    expect(pid in cgroup_processes, "cgroup.procs omitted the process leader")
    print("PROC_TASK_RUNTIME_PROBE_PASS failures: 0")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"PROC_TASK_RUNTIME_PROBE_FAIL: {error}", file=sys.stderr)
        sys.exit(1)
