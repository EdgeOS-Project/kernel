/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux get_mempolicy ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_get_mempolicy
#define SYS_get_mempolicy __NR_get_mempolicy
#endif

#define MPOL_DEFAULT 0
#define MPOL_F_NODE 1u
#define MPOL_F_ADDR 2u
#define MPOL_F_MEMS_ALLOWED 4u

static int failures;

static long get_mempolicy_call(int *mode, unsigned long *mask,
                               unsigned long maxnode, void *address,
                               unsigned long flags) {
    return syscall(SYS_get_mempolicy, mode, mask, maxnode, address, flags);
}

static void expect_result(const char *name, long actual, long expected) {
    if (actual != expected) {
        fprintf(stderr, "FAIL %-30s actual=%ld expected=%ld errno=%d\n",
                name, actual, expected, errno);
        ++failures;
    } else {
        printf("ok %-32s %ld\n", name, actual);
    }
}

static void expect_errno(const char *name, long result, int expected) {
    if (result != -1 || errno != expected) {
        fprintf(stderr,
                "FAIL %-30s result=%ld errno=%d expected_errno=%d\n",
                name, result, errno, expected);
        ++failures;
    } else {
        printf("ok %-32s errno=%d\n", name, errno);
    }
}

int main(void) {
    unsigned long mask[16];
    int mode = -1;
    unsigned char *page;

    memset(mask, 0xa5, sizeof(mask));
    expect_result("default policy",
                  get_mempolicy_call(&mode, mask, 1024, NULL, 0), 0);
    expect_result("default mode", mode, MPOL_DEFAULT);
    expect_result("default mask empty", mask[0], 0);

    memset(mask, 0, sizeof(mask));
    mode = -1;
    expect_result("allowed node query",
                  get_mempolicy_call(&mode, mask, 1024, NULL,
                                     MPOL_F_MEMS_ALLOWED), 0);
    expect_result("node zero allowed", mask[0] & 1ul, 1);

    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    page[0] = 1;
    mode = -1;
    expect_result("address node query",
                  get_mempolicy_call(&mode, NULL, 0, page,
                                     MPOL_F_ADDR | MPOL_F_NODE), 0);
    expect_result("address on node zero", mode, 0);

    errno = 0;
    expect_errno("reject unknown flags",
                 get_mempolicy_call(NULL, NULL, 0, NULL, 8u), EINVAL);
    errno = 0;
    expect_errno("reject conflicting flags",
                 get_mempolicy_call(NULL, mask, 1024, NULL,
                                    MPOL_F_MEMS_ALLOWED | MPOL_F_NODE),
                 EINVAL);
    errno = 0;
    expect_errno("reject missing address",
                 get_mempolicy_call(NULL, NULL, 0, NULL, MPOL_F_ADDR),
                 EFAULT);
    errno = 0;
    expect_errno("reject unexpected address",
                 get_mempolicy_call(NULL, NULL, 0, page, 0), EINVAL);
    errno = 0;
    expect_errno("reject node without address",
                 get_mempolicy_call(NULL, NULL, 0, NULL, MPOL_F_NODE),
                 EINVAL);
    errno = 0;
    expect_errno("reject zero maxnode",
                 get_mempolicy_call(NULL, mask, 0, NULL, 0), EINVAL);
    munmap(page, 4096);

    if (failures) {
        fprintf(stderr, "MEMPOLICY_ABI_PROBE_FAIL failures=%d\n", failures);
        return 1;
    }
    puts("MEMPOLICY_ABI_PROBE_PASS");
    return 0;
}
