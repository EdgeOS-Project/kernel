/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define STRING_H
#define EDGEOS_HOST_TEST 1
static uint64_t current_task = 7, now_us = 1000;
static int current_pid = 42;
static uint32_t clock_reads;
uint64_t arch_cpu_current_task(void) { return current_task; }
int kernel_current_pid(void) { return current_pid; }
uint64_t boottime_monotonic_us(void) { ++clock_reads; return now_us; }
#include "../../src/vfs/profile.c"

static void early_return(void) {
    VFS_PROFILE_SCOPE(VFS_PROFILE_MOUNT);
    vfs_profile_scope.work = 11;
    vfs_profile_scope.hits = 1;
    now_us += 5;
    return;
}
int main(void) {
    char output[4096];
    vfs_profile_scope_t old;
    assert(!vfs_profile_begin(VFS_PROFILE_MOUNT).generation);
    assert(!clock_reads);
    assert(vfs_profile_control("bad", 3) < 0);
    assert(vfs_profile_control("start\n", 6) == 0);
    for (uint32_t i = 0; i < 1024; ++i) {
        vfs_profile_scope_t scope = vfs_profile_begin(VFS_PROFILE_USER_STRING);
        scope.work = 40;
        now_us += 10;
        vfs_profile_end(&scope);
    }
    assert(profile.rows[VFS_PROFILE_USER_STRING].calls == 1024);
    assert(profile.rows[VFS_PROFILE_USER_STRING].work == 40960);
    uint64_t samples = profile.rows[VFS_PROFILE_USER_STRING].samples;
    assert(samples > 32 && samples < 96);
    assert(profile.rows[VFS_PROFILE_USER_STRING].sampled_us == samples * 10);
    assert(clock_reads == samples * 2);
    current_task = 8;
    assert(!vfs_profile_begin(VFS_PROFILE_USER_STRING).generation);
    current_task = 7;
    current_pid = 43;
    assert(!vfs_profile_begin(VFS_PROFILE_USER_STRING).generation);
    current_pid = 42;
    early_return();
    assert(profile.rows[VFS_PROFILE_MOUNT].work == 11);
    assert(profile.rows[VFS_PROFILE_MOUNT].hits == 1);
    assert(profile.rows[VFS_PROFILE_MOUNT].sampled_us ==
           profile.rows[VFS_PROFILE_MOUNT].samples * 5);
    old = vfs_profile_begin(VFS_PROFILE_MOUNT);
    old.work = 123456;
    assert(vfs_profile_control("counts", 6) == 0);
    vfs_profile_end(&old);
    assert(!profile.rows[VFS_PROFILE_MOUNT].work);
    clock_reads = 0;
    early_return();
    assert(!clock_reads && !profile.rows[VFS_PROFILE_MOUNT].samples);
    assert(profile.rows[VFS_PROFILE_MOUNT].calls == 1);
    assert(vfs_profile_control("stop", 4) == 0);
    assert(!vfs_profile_begin(VFS_PROFILE_MOUNT).generation);
    int length = vfs_profile_render(output, sizeof(output) - 1);
    assert(length > 0);
    output[length] = 0;
    assert(strstr(output, "sample_stride 0\n"));
    assert(strstr(output, "mount 1 11 1 0 0 0\n"));
    assert(strstr(output, "enabled 0\n"));
    assert(vfs_profile_render(output, 8) < 0);
    puts("vfs_profile_unit: PASS");
    return 0;
}
