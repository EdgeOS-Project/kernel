/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/keyring_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/pipe_runtime.h"
#include "kernel/vfs_runtime.h"

static uint64_t test_time_us = 1000000u;
static uint32_t parent_thread_count = 1u;
static kernel_linux_identity_t parent_process_identity;
static kernel_pipe_runtime_t watch_pipe;

typedef struct test_key_notification {
    uint32_t type_subtype;
    uint32_t info;
    uint32_t key_id;
    uint32_t auxiliary;
} test_key_notification_t;

typedef struct test_removal_notification {
    uint32_t type_subtype;
    uint32_t info;
    uint64_t key_id;
} test_removal_notification_t;

typedef struct test_keyctl_dh_params {
    int32_t private_key;
    int32_t prime;
    int32_t base;
} test_keyctl_dh_params_t;

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

static kernel_linux_identity_t identity_in_user_namespace(
    int32_t tid, int32_t tgid, int32_t ppid, uint32_t uid,
    uint32_t user_namespace_id) {
    kernel_linux_identity_t result = identity(tid, tgid, ppid, uid);
    result.user_namespace_id = user_namespace_id;
    return result;
}

int kernel_process_linux_identity(int32_t pid,
                                  kernel_linux_identity_t *result) {
    if (!result || pid != parent_process_identity.global_tid) return -1;
    *result = parent_process_identity;
    return 0;
}

uint32_t kernel_arch_proc_thread_group_count(int32_t tgid) {
    return tgid == parent_process_identity.global_tgid ?
        parent_thread_count : 0u;
}

int kernel_vfs_describe_descriptor(
        int32_t descriptor, kernel_vfs_descriptor_t *description) {
    if (!description || descriptor != 77) return -EDGE_LINUX_EBADF;
    memset(description, 0, sizeof(*description));
    description->kind = KERNEL_VFS_DESCRIPTOR_PIPE;
    description->pipe = &watch_pipe;
    description->readable = 1;
    return 0;
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
    int64_t child_session;

    kernel_pipe_object_initialize(&watch_pipe);
    assert(kernel_pipe_notification_mode_set(&watch_pipe, 1) == 0);
    assert(kernel_pipe_watch_size_set(&watch_pipe, 1u) == 0);

    arguments[0] = (uint64_t)(int64_t)EDGE_LINUX_KEY_SPEC_SESSION_KEYRING;
    arguments[1] = 1;
    session = kernel_keyring_keyctl(
        &parent, &access, EDGE_LINUX_KEYCTL_GET_KEYRING_ID, arguments);
    assert(session > 0);
    parent_process_identity = parent;

    key = kernel_keyring_add_key(
        &parent, &access, (uint64_t)(uintptr_t)"user",
        (uint64_t)(uintptr_t)"unit-key",
        (uint64_t)(uintptr_t)payload, sizeof(payload) - 1u,
        EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
    assert(key > 0);

    {
        static const uint8_t private_value[] = {1u};
        static const uint8_t prime_value[] =
            "\xff\xff\xff\xff\xff\xff\xff\xff\xad\xf8\x54\x58\xa2\xbb\x4a\x9a"
            "\xaf\xdc\x56\x20\x27\x3d\x3c\xf1\xd8\xb9\xc5\x83\xce\x2d\x36\x95"
            "\xa9\xe1\x36\x41\x14\x64\x33\xfb\xcc\x93\x9d\xce\x24\x9b\x3e\xf9"
            "\x7d\x2f\xe3\x63\x63\x0c\x75\xd8\xf6\x81\xb2\x02\xae\xc4\x61\x7a"
            "\xd3\xdf\x1e\xd5\xd5\xfd\x65\x61\x24\x33\xf5\x1f\x5f\x06\x6e\xd0"
            "\x85\x63\x65\x55\x3d\xed\x1a\xf3\xb5\x57\x13\x5e\x7f\x57\xc9\x35"
            "\x98\x4f\x0c\x70\xe0\xe6\x8b\x77\xe2\xa6\x89\xda\xf3\xef\xe8\x72"
            "\x1d\xf1\x58\xa1\x36\xad\xe7\x35\x30\xac\xca\x4f\x48\x3a\x79\x7a"
            "\xbc\x0a\xb1\x82\xb3\x24\xfb\x61\xd1\x08\xa9\x4b\xb2\xc8\xe3\xfb"
            "\xb9\x6a\xda\xb7\x60\xd7\xf4\x68\x1d\x4f\x42\xa3\xde\x39\x4d\xf4"
            "\xae\x56\xed\xe7\x63\x72\xbb\x19\x0b\x07\xa7\xc8\xee\x0a\x6d\x70"
            "\x9e\x02\xfc\xe1\xcd\xf7\xe2\xec\xc0\x34\x04\xcd\x28\x34\x2f\x61"
            "\x91\x72\xfe\x9c\xe9\x85\x83\xff\x8e\x4f\x12\x32\xee\xf2\x81\x83"
            "\xc3\xfe\x3b\x1b\x4c\x6f\xad\x73\x3b\xb5\xfc\xbc\x2e\xc2\x20\x05"
            "\xc5\x8e\xf1\x83\x7d\x16\x83\xb2\xc6\xf3\x4a\x26\xc1\xb2\xef\xfa"
            "\x88\x6b\x42\x38\x61\x28\x5c\x97\xff\xff\xff\xff\xff\xff\xff\xff";
        static const uint8_t base_value[] = {2u};
        test_keyctl_dh_params_t parameters;
        uint8_t shared_value[sizeof(prime_value) - 1u];

        parameters.private_key = (int32_t)kernel_keyring_add_key(
            &parent, &access, (uint64_t)(uintptr_t)"user",
            (uint64_t)(uintptr_t)"dh-private",
            (uint64_t)(uintptr_t)private_value, sizeof(private_value),
            EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
        parameters.prime = (int32_t)kernel_keyring_add_key(
            &parent, &access, (uint64_t)(uintptr_t)"user",
            (uint64_t)(uintptr_t)"dh-prime",
            (uint64_t)(uintptr_t)prime_value, sizeof(prime_value) - 1u,
            EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
        parameters.base = (int32_t)kernel_keyring_add_key(
            &parent, &access, (uint64_t)(uintptr_t)"user",
            (uint64_t)(uintptr_t)"dh-base",
            (uint64_t)(uintptr_t)base_value, sizeof(base_value),
            EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
        assert(parameters.private_key > 0 && parameters.prime > 0 &&
               parameters.base > 0);

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = (uint64_t)(uintptr_t)&parameters;
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == (int64_t)sizeof(shared_value));
        memset(shared_value, 0xff, sizeof(shared_value));
        arguments[1] = (uint64_t)(uintptr_t)&shared_value;
        arguments[2] = sizeof(shared_value);
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == (int64_t)sizeof(shared_value));
        for (uint32_t index = 0; index + 1u < sizeof(shared_value);
             ++index)
            assert(shared_value[index] == 0u);
        assert(shared_value[sizeof(shared_value) - 1u] == 2u);
    }

    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    arguments[1] = 77u;
    arguments[2] = 42u;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_WATCH_KEY,
               arguments) == 0);
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_WATCH_KEY,
               arguments) == -EDGE_LINUX_EBUSY);
    arguments[1] = 78u;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_WATCH_KEY,
               arguments) == -EDGE_LINUX_EINVAL);

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
    {
        test_key_notification_t notification;

        assert(kernel_pipe_read_kernel(
                   &watch_pipe, &notification,
                   sizeof(notification)) == sizeof(notification));
        assert((notification.type_subtype & 0x00ffffffu) == 1u);
        assert((notification.type_subtype >> 24u) == 1u);
        assert((notification.info & 0x7fu) == sizeof(notification));
        assert(((notification.info >> 8u) & 0xffu) == 42u);
        assert(notification.key_id == (uint32_t)key);
        assert(notification.auxiliary == 0u);
    }

    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    arguments[1] = 77u;
    arguments[2] = (uint64_t)(int64_t)-1;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_WATCH_KEY,
               arguments) == 0);
    {
        test_removal_notification_t notification;

        assert(kernel_pipe_read_kernel(
                   &watch_pipe, &notification,
                   sizeof(notification)) == sizeof(notification));
        assert(notification.type_subtype == 0u);
        assert((notification.info & 0x7fu) == sizeof(notification));
        assert(((notification.info >> 8u) & 0xffu) == 42u);
        assert(notification.key_id == (uint64_t)(uint32_t)key);
    }
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_WATCH_KEY,
               arguments) == -EDGE_LINUX_EBADSLT);

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
    assert((capabilities[0] & 2u) != 0u);
    assert((capabilities[1] & 1u) != 0u);
    assert((capabilities[1] & 4u) != 0u);
    for (uint32_t index = 2; index < sizeof(capabilities); ++index)
        assert(capabilities[index] == 0u);

    memset(arguments, 0, sizeof(arguments));
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_ASSUME_AUTHORITY,
               arguments) == 0);
    arguments[0] = UINT64_MAX;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_ASSUME_AUTHORITY,
               arguments) == -EDGE_LINUX_EINVAL);
    arguments[0] = (uint64_t)key;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_ASSUME_AUTHORITY,
               arguments) == -EDGE_LINUX_ENOKEY);
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_INSTANTIATE,
               arguments) == -EDGE_LINUX_EPERM);
    arguments[2] = 1024u * 1024u;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_INSTANTIATE,
               arguments) == -EDGE_LINUX_EINVAL);
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)key;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_NEGATE,
               arguments) == -EDGE_LINUX_EPERM);
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_REJECT,
               arguments) == -EDGE_LINUX_EINVAL);
    arguments[2] = EDGE_LINUX_ENOKEY;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_REJECT,
               arguments) == -EDGE_LINUX_EPERM);
    memset(arguments, 0, sizeof(arguments));
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
               arguments) == -EDGE_LINUX_EINVAL);
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_PKEY_QUERY,
               arguments) == -EDGE_LINUX_EOPNOTSUPP);

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

    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)(uintptr_t)"child-session";
    child_session = kernel_keyring_keyctl(
        &child, &access, EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING,
        arguments);
    assert(child_session > 0 && child_session != session);
    memset(arguments, 0, sizeof(arguments));
    assert(kernel_keyring_keyctl(
               &child, &access, EDGE_LINUX_KEYCTL_SESSION_TO_PARENT,
               arguments) == 0);
    arguments[0] =
        (uint64_t)(int64_t)EDGE_LINUX_KEY_SPEC_SESSION_KEYRING;
    assert(kernel_keyring_keyctl(
               &parent, &access, EDGE_LINUX_KEYCTL_GET_KEYRING_ID,
               arguments) == child_session);

    arguments[0] = (uint64_t)(uintptr_t)"blocked-session";
    assert(kernel_keyring_keyctl(
               &child, &access, EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING,
               arguments) > 0);
    parent_thread_count = 2u;
    memset(arguments, 0, sizeof(arguments));
    assert(kernel_keyring_keyctl(
               &child, &access, EDGE_LINUX_KEYCTL_SESSION_TO_PARENT,
               arguments) == -EDGE_LINUX_EPERM);
    parent_thread_count = 1u;
    {
        kernel_linux_identity_t stranger_child =
            identity(201, 201, 100, 2000);
        assert(kernel_keyring_keyctl(
                   &stranger_child, &access,
                   EDGE_LINUX_KEYCTL_SESSION_TO_PARENT,
                   arguments) == -EDGE_LINUX_EPERM);
    }

    {
        kernel_linux_identity_t init = identity(1, 1, 0, 3000);
        kernel_linux_identity_t init_child = identity(401, 401, 1, 3000);
        int64_t init_child_session;

        memset(arguments, 0, sizeof(arguments));
        arguments[0] =
            (uint64_t)(int64_t)EDGE_LINUX_KEY_SPEC_SESSION_KEYRING;
        arguments[1] = 1u;
        assert(kernel_keyring_keyctl(
                   &init, &access, EDGE_LINUX_KEYCTL_GET_KEYRING_ID,
                   arguments) > 0);
        arguments[0] = (uint64_t)(uintptr_t)"init-child-session";
        init_child_session = kernel_keyring_keyctl(
            &init_child, &access,
            EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING, arguments);
        assert(init_child_session > 0);
        parent_process_identity = init;
        parent_thread_count = 1u;
        memset(arguments, 0, sizeof(arguments));
        assert(kernel_keyring_keyctl(
                   &init_child, &access,
                   EDGE_LINUX_KEYCTL_SESSION_TO_PARENT,
                   arguments) == 0);
        arguments[0] =
            (uint64_t)(int64_t)EDGE_LINUX_KEY_SPEC_SESSION_KEYRING;
        assert(kernel_keyring_keyctl(
                   &init, &access, EDGE_LINUX_KEYCTL_GET_KEYRING_ID,
                   arguments) == init_child_session);
        parent_process_identity = parent;
    }

    {
        kernel_linux_identity_t namespace_parent =
            identity_in_user_namespace(300, 300, 1, 1000, 17u);
        kernel_linux_identity_t namespace_peer =
            identity_in_user_namespace(301, 301, 1, 1000, 18u);
        int64_t first;
        int64_t second;
        int64_t first_key;
        int64_t second_key;

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = (uint64_t)(uintptr_t)"namespace-session";
        first = kernel_keyring_keyctl(
            &namespace_parent, &access,
            EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING, arguments);
        second = kernel_keyring_keyctl(
            &namespace_peer, &access,
            EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING, arguments);
        assert(first > 0 && second > 0 && first != second);

        first_key = kernel_keyring_add_key(
            &namespace_parent, &access,
            (uint64_t)(uintptr_t)"user",
            (uint64_t)(uintptr_t)"namespace-key",
            (uint64_t)(uintptr_t)payload, sizeof(payload) - 1u,
            EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
        second_key = kernel_keyring_add_key(
            &namespace_peer, &access,
            (uint64_t)(uintptr_t)"user",
            (uint64_t)(uintptr_t)"namespace-key",
            (uint64_t)(uintptr_t)replacement,
            sizeof(replacement) - 1u,
            EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
        assert(first_key > 0 && second_key > 0 && first_key != second_key);
        assert(kernel_keyring_request_key(
                   &namespace_parent, &access,
                   (uint64_t)(uintptr_t)"user",
                   (uint64_t)(uintptr_t)"namespace-key", 0, 0) ==
               first_key);
        assert(kernel_keyring_request_key(
                   &namespace_peer, &access,
                   (uint64_t)(uintptr_t)"user",
                   (uint64_t)(uintptr_t)"namespace-key", 0, 0) ==
               second_key);
        kernel_keyring_task_exit(300, 300, 1);
        kernel_keyring_task_exit(301, 301, 1);
    }

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
