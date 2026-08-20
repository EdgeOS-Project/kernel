/* SPDX-License-Identifier: MPL-2.0 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/landlock_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    (void)identity;
    return -1;
}

static int expect(const char *name, int actual, int expected) {
    if (actual == expected) return 0;
    fprintf(stderr, "%s: expected %d, got %d\n", name, expected, actual);
    return 1;
}

int main(void) {
    const uint64_t read = EDGE_LINUX_LANDLOCK_ACCESS_FS_READ_FILE;
    const uint64_t write = EDGE_LINUX_LANDLOCK_ACCESS_FS_WRITE_FILE;
    const uint64_t refer = EDGE_LINUX_LANDLOCK_ACCESS_FS_REFER;
    int first;
    int second;
    int third;
    int fourth;
    int failed = 0;

    failed |= expect("empty ruleset",
                     kernel_landlock_ruleset_create(0),
                     -EDGE_LINUX_ENOMSG);
    failed |= expect("unknown access",
                     kernel_landlock_ruleset_create(1ULL << 63),
                     -EDGE_LINUX_EINVAL);

    first = kernel_landlock_ruleset_create(read | write);
    if (first < 0) return 1;
    failed |= expect("empty rule",
                     kernel_landlock_ruleset_add_path(first, "/srv", 0),
                     -EDGE_LINUX_ENOMSG);
    failed |= expect("rule outside handled mask",
                     kernel_landlock_ruleset_add_path(
                         first, "/srv", EDGE_LINUX_LANDLOCK_ACCESS_FS_EXECUTE),
                     -EDGE_LINUX_EINVAL);
    failed |= expect("add read subtree",
                     kernel_landlock_ruleset_add_path(
                         first, "/srv/allowed", read), 0);
    failed |= expect("restrict first layer",
                     kernel_landlock_restrict_task(100, 100, first), 0);
    failed |= expect("allowed descendant",
                     kernel_landlock_check_path_for_task(
                         100, "/srv/allowed/file", read), 0);
    failed |= expect("denied write",
                     kernel_landlock_check_path_for_task(
                         100, "/srv/allowed/file", write),
                     -EDGE_LINUX_EACCES);
    failed |= expect("denied outside subtree",
                     kernel_landlock_check_path_for_task(
                         100, "/srv/denied", read),
                     -EDGE_LINUX_EACCES);
    failed |= expect("refer denied by default",
                     kernel_landlock_check_refer_for_task(
                         100, "/srv/allowed/file", "/srv/later/file"),
                     -EDGE_LINUX_EXDEV);

    failed |= expect("mutate source ruleset",
                     kernel_landlock_ruleset_add_path(
                         first, "/srv/later", read), 0);
    failed |= expect("restricted layer is snapshot",
                     kernel_landlock_check_path_for_task(
                         100, "/srv/later/file", read),
                     -EDGE_LINUX_EACCES);

    second = kernel_landlock_ruleset_create(read);
    if (second < 0) return 1;
    failed |= expect("add nested rule",
                     kernel_landlock_ruleset_add_path(
                         second, "/srv/allowed/deep", read), 0);
    failed |= expect("stack second layer",
                     kernel_landlock_restrict_task(100, 100, second), 0);
    failed |= expect("stacked intersection denies parent",
                     kernel_landlock_check_path_for_task(
                         100, "/srv/allowed/file", read),
                     -EDGE_LINUX_EACCES);
    failed |= expect("stacked intersection allows nested",
                     kernel_landlock_check_path_for_task(
                         100, "/srv/allowed/deep/file", read), 0);

    third = kernel_landlock_ruleset_create(read | refer);
    if (third < 0) return 1;
    failed |= expect("add source refer rule",
                     kernel_landlock_ruleset_add_path(
                         third, "/source", refer), 0);
    failed |= expect("add destination refer rule",
                     kernel_landlock_ruleset_add_path(
                         third, "/destination", read | refer), 0);
    failed |= expect("restrict refer layer",
                     kernel_landlock_restrict_task(200, 200, third), 0);
    failed |= expect("refer cannot gain access",
                     kernel_landlock_check_refer_for_task(
                         200, "/source/file", "/destination/file"),
                     -EDGE_LINUX_EXDEV);
    failed |= expect("extend source rule",
                     kernel_landlock_ruleset_add_path(
                         third, "/source", read), 0);
    failed |= expect("restricted refer layer is snapshot",
                     kernel_landlock_check_refer_for_task(
                         200, "/source/file", "/destination/file"),
                     -EDGE_LINUX_EXDEV);

    fourth = kernel_landlock_ruleset_create(read | refer);
    if (fourth < 0) return 1;
    failed |= expect("add balanced source rule",
                     kernel_landlock_ruleset_add_path(
                         fourth, "/source", read | refer), 0);
    failed |= expect("add balanced destination rule",
                     kernel_landlock_ruleset_add_path(
                         fourth, "/destination", read | refer), 0);
    failed |= expect("restrict balanced refer layer",
                     kernel_landlock_restrict_task(201, 201, fourth), 0);
    failed |= expect("balanced refer allowed",
                     kernel_landlock_check_refer_for_task(
                         201, "/source/file", "/destination/file"), 0);

    failed |= expect("clone task domain",
                     kernel_landlock_task_clone(100, 101, 101), 0);
    failed |= expect("child inherited denial",
                     kernel_landlock_check_path_for_task(
                         101, "/srv/allowed/file", read),
                     -EDGE_LINUX_EACCES);
    kernel_landlock_task_exit(101, 101, 0);
    failed |= expect("exited child is unrestricted",
                     kernel_landlock_check_path_for_task(
                         101, "/srv/allowed/file", read), 0);

    kernel_landlock_task_exit(100, 100, 1);
    kernel_landlock_task_exit(200, 200, 1);
    kernel_landlock_task_exit(201, 201, 1);
    kernel_landlock_ruleset_release(first);
    kernel_landlock_ruleset_release(second);
    kernel_landlock_ruleset_release(third);
    kernel_landlock_ruleset_release(fourth);
    if (failed) return 1;
    puts("LANDLOCK_RUNTIME_UNIT_PASS");
    return 0;
}
