#!/usr/bin/env python3
"""Validate Linux-visible rename, rmdir, and cgroup namespace semantics."""

import errno
import os
import shutil
import subprocess


EXT4_BASE = "/root/edgeos-vfs-namespace-test"
TMPFS_BASE = "/run/edgeos-vfs-namespace-test"
CGROUP_BASE = "/sys/fs/cgroup"


def remove_tree(path):
    if os.path.lexists(path):
        shutil.rmtree(path)


def expect_errno(expected, operation, description):
    try:
        operation()
    except OSError as error:
        if error.errno != expected:
            raise AssertionError(
                f"{description}: expected errno {expected}, got {error.errno}"
            ) from error
        return
    raise AssertionError(f"{description}: operation unexpectedly succeeded")


def write_text(path, value):
    with open(path, "w", encoding="ascii") as output:
        output.write(value)


def read_text(path):
    with open(path, "r", encoding="ascii") as source:
        return source.read()


def validate_filesystem(base, check_open_replacement):
    remove_tree(base)
    os.makedirs(base)

    same_parent_source = os.path.join(base, "same-parent-source")
    same_parent_target = os.path.join(base, "same-parent-target")
    os.makedirs(os.path.join(same_parent_source, "child"))
    write_text(os.path.join(same_parent_source, "child", "payload"), "same-parent")
    os.rename(same_parent_source, same_parent_target)
    assert not os.path.exists(same_parent_source)
    assert read_text(os.path.join(same_parent_target, "child", "payload")) == "same-parent"

    old_parent = os.path.join(base, "old-parent")
    new_parent = os.path.join(base, "new-parent")
    os.makedirs(os.path.join(old_parent, "moving", "nested"))
    os.makedirs(new_parent)
    moved = os.path.join(new_parent, "moved")
    os.rename(os.path.join(old_parent, "moving"), moved)
    assert os.stat(os.path.join(moved, "..")).st_ino == os.stat(new_parent).st_ino
    assert os.path.isdir(os.path.join(moved, "nested"))

    replacement_source = os.path.join(base, "replacement-source")
    replacement_target = os.path.join(base, "replacement-target")
    os.makedirs(replacement_source)
    os.makedirs(replacement_target)
    write_text(os.path.join(replacement_source, "kept"), "directory-replacement")
    target_fd = os.open(replacement_target, os.O_RDONLY | os.O_DIRECTORY)
    target_inode = os.fstat(target_fd).st_ino
    os.rename(replacement_source, replacement_target)
    assert read_text(os.path.join(replacement_target, "kept")) == "directory-replacement"
    assert os.fstat(target_fd).st_ino == target_inode
    os.close(target_fd)

    nonempty_source = os.path.join(base, "nonempty-source")
    nonempty_target = os.path.join(base, "nonempty-target")
    os.makedirs(nonempty_source)
    os.makedirs(nonempty_target)
    write_text(os.path.join(nonempty_target, "occupied"), "busy")
    expect_errno(
        errno.ENOTEMPTY,
        lambda: os.rename(nonempty_source, nonempty_target),
        "rename over nonempty directory",
    )

    cycle = os.path.join(base, "cycle")
    os.makedirs(os.path.join(cycle, "child"))
    expect_errno(
        errno.EINVAL,
        lambda: os.rename(cycle, os.path.join(cycle, "child", "cycle")),
        "rename directory into descendant",
    )

    file_source = os.path.join(base, "file-source")
    file_target = os.path.join(base, "file-target")
    write_text(file_source, "new-data")
    write_text(file_target, "old-data")
    old_fd = os.open(file_target, os.O_RDONLY)
    os.rename(file_source, file_target)
    assert read_text(file_target) == "new-data"
    if check_open_replacement:
        assert os.read(old_fd, 32) == b"old-data"
    os.close(old_fd)

    remove_tree(base)


def validate_cross_mount_rename():
    source = os.path.join(TMPFS_BASE, "cross-mount-source")
    target = os.path.join(EXT4_BASE, "cross-mount-target")
    remove_tree(TMPFS_BASE)
    remove_tree(EXT4_BASE)
    os.makedirs(TMPFS_BASE)
    os.makedirs(EXT4_BASE)
    write_text(source, "cross-mount")
    expect_errno(
        errno.EXDEV,
        lambda: os.rename(source, target),
        "cross-mount rename",
    )
    assert os.path.exists(source)
    assert not os.path.exists(target)
    remove_tree(TMPFS_BASE)
    remove_tree(EXT4_BASE)


def validate_cgroup():
    subprocess.run(["rc-service", "cgroups", "start"], check=True)
    cpu_pressure = read_text(os.path.join(CGROUP_BASE, "cpu.pressure"))
    pressure_lines = cpu_pressure.splitlines()
    assert len(pressure_lines) == 2
    assert pressure_lines[0].startswith("some avg10=")
    assert pressure_lines[1].startswith("full avg10=")
    assert all(" total=" in line for line in pressure_lines)
    io_pressure = read_text(os.path.join(CGROUP_BASE, "io.pressure"))
    io_pressure_lines = io_pressure.splitlines()
    assert len(io_pressure_lines) == 2
    assert io_pressure_lines[0].startswith("some avg10=")
    assert io_pressure_lines[1].startswith("full avg10=")
    assert all(" total=" in line for line in io_pressure_lines)
    assert not os.path.exists(os.path.join(CGROUP_BASE, "cgroup.kill"))
    assert not os.path.exists(os.path.join(CGROUP_BASE, "cgroup.freeze"))
    populated = os.path.join(CGROUP_BASE, "edgeos-populated-test")
    kill_group = os.path.join(CGROUP_BASE, "edgeos-kill-test")
    moving = os.path.join(CGROUP_BASE, "edgeos-moving-test")
    moved = os.path.join(CGROUP_BASE, "edgeos-moved-test")
    for path in (populated, kill_group, moving, moved):
        try:
            os.rmdir(path)
        except FileNotFoundError:
            pass

    os.mkdir(populated)
    sleeper = subprocess.Popen(["sleep", "60"])
    try:
        write_text(os.path.join(populated, "cgroup.procs"), f"{sleeper.pid}\n")
        expect_errno(
            errno.EBUSY,
            lambda: os.rmdir(populated),
            "remove populated cgroup",
        )
    finally:
        sleeper.terminate()
        sleeper.wait()
    os.rmdir(populated)

    os.mkdir(kill_group)
    assert os.path.exists(os.path.join(kill_group, "cgroup.kill"))
    assert os.path.exists(os.path.join(kill_group, "cgroup.freeze"))
    sleeper = subprocess.Popen(["sleep", "60"])
    write_text(os.path.join(kill_group, "cgroup.procs"), f"{sleeper.pid}\n")
    write_text(os.path.join(kill_group, "cgroup.kill"), "1\n")
    assert sleeper.wait(timeout=5) == -9
    os.rmdir(kill_group)

    os.mkdir(moving)
    write_text(os.path.join(moving, "cgroup.procs"), f"{os.getpid()}\n")
    assert read_text("/proc/self/cgroup").strip() == "0::/edgeos-moving-test"
    os.rename(moving, moved)
    assert read_text("/proc/self/cgroup").strip() == "0::/edgeos-moved-test"
    write_text(os.path.join(CGROUP_BASE, "cgroup.procs"), f"{os.getpid()}\n")
    os.rmdir(moved)


def main():
    validate_filesystem(EXT4_BASE, check_open_replacement=True)
    validate_filesystem(TMPFS_BASE, check_open_replacement=False)
    validate_cross_mount_rename()
    validate_cgroup()
    print("VFS_NAMESPACE_SEMANTICS_PASS")


if __name__ == "__main__":
    main()
