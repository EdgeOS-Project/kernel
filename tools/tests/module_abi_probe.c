/* SPDX-License-Identifier: MPL-2.0 */
/* Linux module syscall validation-order probe. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LINUX_CAPABILITY_VERSION_3 UINT32_C(0x20080522)
#define LINUX_CAP_SYS_MODULE 16u

struct linux_capability_header {
    uint32_t version;
    int32_t pid;
};

struct linux_capability_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static int has_module_capability(void) {
    struct linux_capability_header header = {
        .version = LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct linux_capability_data data[2] = {{0}};

    if (syscall(SYS_capget, &header, data) != 0) return 0;
    return (data[LINUX_CAP_SYS_MODULE / 32u].effective &
            (UINT32_C(1) << (LINUX_CAP_SYS_MODULE % 32u))) != 0;
}

static int expect_errno(const char *name, long result, int expected) {
    int actual = result < 0 ? errno : 0;

    printf("%s\tresult=%ld\terrno=%d\n", name, result, actual);
    return result == -1 && actual == expected ? 0 : 1;
}

int main(void) {
    static const char empty[] = "";
    int privileged = has_module_capability();
    int failures = 0;

    errno = 0;
    failures += expect_errno(
        "init_bad_image",
        syscall(SYS_init_module, (void *)(uintptr_t)1, 1u, empty),
        privileged ? EFAULT : EPERM);
    errno = 0;
    failures += expect_errno(
        "delete_bad_name",
        syscall(SYS_delete_module, (void *)(uintptr_t)1, 0u),
        privileged ? EFAULT : EPERM);
    errno = 0;
    failures += expect_errno(
        "finit_bad_fd", syscall(SYS_finit_module, -1, empty, 0u),
        privileged ? EBADF : EPERM);
    errno = 0;
    failures += expect_errno(
        "finit_bad_flags", syscall(SYS_finit_module, -1, empty, 0x80000000u),
        privileged ? EINVAL : EPERM);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
