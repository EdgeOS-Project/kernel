/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/keyring_runtime.h"
#include "kernel/linux_errno.h"

static uint64_t test_time_us = 1000000u;

uint64_t boottime_monotonic_us(void) {
    return test_time_us;
}

static int copy_from_user(void *context, void *destination,
                          uint64_t source, uint64_t length) {
    (void)context;
    if (!destination || (!source && length)) return -1;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}

static int copy_to_user(void *context, uint64_t destination,
                        const void *source, uint64_t length) {
    (void)context;
    if ((!destination && length) || !source) return -1;
    memcpy((void *)(uintptr_t)destination, source, (size_t)length);
    return 0;
}

static kernel_linux_identity_t identity(int32_t tid, int32_t tgid,
                                        int32_t ppid, uint32_t uid) {
    kernel_linux_identity_t result;
    memset(&result, 0, sizeof(result));
    result.global_tid = tid;
    result.global_tgid = tgid;
    result.global_ppid = ppid;
    result.tid = tid;
    result.tgid = tgid;
    result.ppid = ppid;
    result.uid = uid;
    result.euid = uid;
    result.suid = uid;
    result.fsuid = uid;
    result.gid = uid;
    result.egid = uid;
    result.sgid = uid;
    result.fsgid = uid;
    return result;
}

int main(void) {
    kernel_linux_identity_t parent = identity(100, 100, 1, 1000);
    kernel_linux_identity_t child = identity(101, 101, 100, 1000);
    kernel_linux_identity_t stranger = identity(200, 200, 1, 2000);
    kernel_keyring_user_access_t access = {
        .copy_from_user = copy_from_user,
        .copy_to_user = copy_to_user,
        .context = 0,
    };
    static const char payload[] = "payload";
    static const char replacement[] = "replacement";
    uint64_t arguments[4] = {0};
    char output[128];
    uint8_t capabilities[8];
    int64_t session;
    int64_t key;
    int64_t ring;

    arguments[0] = (uint64_t)(int64_t)EDGE_LINUX_KEY_SPEC_SESSION_KEYRING;
    arguments[1] = 1;
    session = kernel_keyring_keyctl(
        &parent, &access, EDGE_LINUX_KEYCTL_GET_KEYRING_ID, arguments);
    assert(session > 0);

    key = kernel_keyring_add_key(
        &parent, &access, (uint64_t)(uintptr_t)"user",
        (uint64_t)(uintptr_t)"unit-key",
        (uint64_t)(uintptr_t)payload, sizeof(payload) - 1u,
        EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
    assert(key > 0);

    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    arguments[1] = (uint64_t)(uintptr_t)output;
    arguments[2] = sizeof(output);
    memset(output, 0, sizeof(output));
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_READ, arguments) ==
           (int64_t)(sizeof(payload) - 1u));
    assert(memcmp(output, payload, sizeof(payload) - 1u) == 0);

    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    arguments[2] = sizeof(output);
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_GET_SECURITY,
               arguments) == 1);
    arguments[1] = (uint64_t)(uintptr_t)output;
    memset(output, 0xff, sizeof(output));
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_GET_SECURITY,
               arguments) == 1);
    assert(output[0] == 0);

    assert(kernel_keyring_request_key(
               &child, &access, (uint64_t)(uintptr_t)"user",
               (uint64_t)(uintptr_t)"unit-key", 0, 0) == key);
    assert(kernel_keyring_request_key(
               &stranger, &access, (uint64_t)(uintptr_t)"user",
               (uint64_t)(uintptr_t)"unit-key", 0, 0) ==
           -EDGE_LINUX_ENOKEY);

    memset(arguments, 0, sizeof(arguments));
    arguments[0] =
        (uint64_t)(int64_t)EDGE_LINUX_KEY_SPEC_SESSION_KEYRING;
    arguments[1] = (uint64_t)(uintptr_t)"user";
    arguments[2] = (uint64_t)(uintptr_t)"unit-key";
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_SEARCH, arguments) == key);

    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    arguments[1] = (uint64_t)(uintptr_t)replacement;
    arguments[2] = sizeof(replacement) - 1u;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_UPDATE, arguments) == 0);

    ring = kernel_keyring_add_key(
        &parent, &access, (uint64_t)(uintptr_t)"keyring",
        (uint64_t)(uintptr_t)"unit-ring", 0, 0,
        EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
    assert(ring > 0);
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    arguments[1] = (uint64_t)ring;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_LINK, arguments) == 0);
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_UNLINK, arguments) == 0);

    memset(capabilities, 0xff, sizeof(capabilities));
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)(uintptr_t)capabilities;
    arguments[1] = sizeof(capabilities);
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_CAPABILITIES,
               arguments) == 2);
    assert((capabilities[0] & 1u) != 0u);
    for (uint32_t index = 2; index < sizeof(capabilities); ++index)
        assert(capabilities[index] == 0u);

    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    arguments[1] = 1;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_SET_TIMEOUT,
               arguments) == 0);
    test_time_us += 1000001u;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_READ, arguments) ==
           -EDGE_LINUX_EKEYEXPIRED);

    for (int32_t index = 0; index < 512; ++index) {
        kernel_linux_identity_t transient = identity(
            1000 + index, 1000 + index, parent.global_tgid, 1000);
        memset(arguments, 0, sizeof(arguments));
        assert(kernel_keyring_keyctl(
                   &transient, &access,
                   EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING,
                   arguments) > 0);
        kernel_keyring_task_exit(
            transient.global_tid, transient.global_tgid, 1);
    }

    kernel_keyring_task_exit(parent.global_tid, parent.global_tgid, 1);
    puts("keyring_runtime_unit: PASS");
    return 0;
}
