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
static int request_helper_mode;
static int request_helper_calls;

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

typedef struct test_keyctl_kdf_params {
    uint64_t hash_name;
    uint64_t other_info;
    uint32_t other_info_length;
    uint32_t spare[8];
    uint32_t padding;
} test_keyctl_kdf_params_t;

typedef struct test_keyctl_pkey_query {
    uint32_t supported_operations;
    uint32_t key_size;
    uint16_t maximum_data_size;
    uint16_t maximum_signature_size;
    uint16_t maximum_encrypted_size;
    uint16_t maximum_decrypted_size;
    uint32_t spare[10];
} test_keyctl_pkey_query_t;

typedef struct test_keyctl_pkey_parameters {
    int32_t key_id;
    uint32_t input_length;
    uint32_t output_length;
    uint32_t spare[7];
} test_keyctl_pkey_parameters_t;

uint64_t boottime_monotonic_us(void) {
    return test_time_us;
}

void edge_random_fill(void *buffer, uint32_t length) {
    uint8_t *bytes = (uint8_t *)buffer;

    for (uint32_t index = 0; index < length; ++index)
        bytes[index] = (uint8_t)(index + 1u);
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

static int invoke_request_helper(
    void *context, int32_t authorization, int32_t target,
    uint32_t uid, uint32_t gid, int32_t thread_keyring,
    int32_t process_keyring, int32_t session_keyring) {
    kernel_linux_identity_t helper = identity(500, 500, 100, uid);
    kernel_keyring_user_access_t access = {
        .copy_from_user = copy_from_user,
        .copy_to_user = copy_to_user,
        .context = context,
        .iovec_pointer_size = sizeof(uint64_t),
        .keyctl_kdf_pointer_size = sizeof(uint64_t),
    };
    static const char constructed[] = "constructed-payload";
    uint64_t arguments[4] = {0};
    char callout[64] = {0};
    int64_t result;

    (void)gid;
    (void)thread_keyring;
    (void)process_keyring;
    (void)session_keyring;
    ++request_helper_calls;
    assert(kernel_keyring_request_authority_grant(
               &helper, authorization) == 0);
    arguments[0] = (uint64_t)(uint32_t)target;
    result = kernel_keyring_keyctl(
        &helper, &access, EDGE_LINUX_KEYCTL_ASSUME_AUTHORITY, arguments);
    assert(result == authorization);
    arguments[0] =
        (uint64_t)(int64_t)EDGE_LINUX_KEY_SPEC_REQKEY_AUTH_KEY;
    arguments[1] = (uint64_t)(uintptr_t)callout;
    arguments[2] = sizeof(callout);
    assert(kernel_keyring_keyctl(
               &helper, &access, EDGE_LINUX_KEYCTL_READ, arguments) > 0);
    assert(!strcmp(callout, "unit-callout"));
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = (uint64_t)(uint32_t)target;
    if (request_helper_mode == 1) {
        arguments[1] = (uint64_t)(uintptr_t)constructed;
        arguments[2] = sizeof(constructed) - 1u;
        result = kernel_keyring_keyctl(
            &helper, &access, EDGE_LINUX_KEYCTL_INSTANTIATE, arguments);
    } else if (request_helper_mode == 2) {
        arguments[1] = 30u;
        result = kernel_keyring_keyctl(
            &helper, &access, EDGE_LINUX_KEYCTL_NEGATE, arguments);
    } else {
        arguments[1] = 30u;
        arguments[2] = EDGE_LINUX_EACCES;
        result = kernel_keyring_keyctl(
            &helper, &access, EDGE_LINUX_KEYCTL_REJECT, arguments);
    }
    assert(result == 0);
    kernel_keyring_task_exit(helper.global_tid, helper.global_tgid, 1);
    return 0;
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
        .iovec_pointer_size = sizeof(uint64_t),
        .keyctl_kdf_pointer_size = sizeof(uint64_t),
        .invoke_request_helper = invoke_request_helper,
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
        static const uint8_t kdf_expected[48] = {
            0xdau, 0x8eu, 0xc1u, 0x67u, 0x48u, 0x77u, 0x1eu, 0x2eu,
            0x90u, 0x3du, 0x58u, 0x15u, 0xc9u, 0xf7u, 0x86u, 0x73u,
            0x37u, 0x8du, 0x6du, 0x96u, 0xb0u, 0x62u, 0x46u, 0xacu,
            0x57u, 0xfbu, 0xfau, 0xc0u, 0x28u, 0xcfu, 0xb5u, 0x63u,
            0x49u, 0x36u, 0x21u, 0xdeu, 0x31u, 0x31u, 0x7eu, 0x43u,
            0xecu, 0xd1u, 0xcdu, 0x70u, 0xffu, 0x78u, 0x6cu, 0x1bu,
        };
        static const uint8_t kdf_sha224_expected[44] = {
            0xcfu, 0xa4u, 0xf2u, 0x23u, 0x6bu, 0xe1u, 0x85u, 0x11u,
            0x34u, 0x66u, 0x72u, 0xbfu, 0x46u, 0x8fu, 0xa6u, 0x03u,
            0xc4u, 0xe2u, 0x99u, 0xabu, 0x3eu, 0xd0u, 0x4au, 0x73u,
            0x5eu, 0xc5u, 0x08u, 0x25u, 0xccu, 0x76u, 0xb1u, 0x68u,
            0xe8u, 0x12u, 0x59u, 0xe5u, 0xa7u, 0xf5u, 0xd8u, 0x62u,
            0x46u, 0xbdu, 0x5bu, 0xb7u,
        };
        static const uint8_t kdf_sha1_expected[48] = {
            0x3au, 0x26u, 0xe3u, 0x07u, 0xb3u, 0x0au, 0xb3u, 0xefu,
            0x18u, 0x5du, 0x98u, 0xf9u, 0x56u, 0xf9u, 0x1eu, 0x0du,
            0x2cu, 0x79u, 0x76u, 0x52u, 0x8cu, 0x54u, 0xffu, 0xb6u,
            0x00u, 0xa2u, 0xe9u, 0x2fu, 0x58u, 0xb7u, 0x35u, 0xf4u,
            0xb8u, 0x24u, 0x2cu, 0x4eu, 0x33u, 0x77u, 0x2du, 0x85u,
            0xf6u, 0x60u, 0x0bu, 0xf4u, 0xf4u, 0xc9u, 0x15u, 0x78u,
        };
        static const uint8_t kdf_sha384_expected[48] = {
            0x0cu, 0xb6u, 0xabu, 0x22u, 0xb8u, 0xc9u, 0xc3u, 0x10u,
            0x83u, 0x83u, 0x2du, 0xe8u, 0x10u, 0x68u, 0x43u, 0x2du,
            0x52u, 0x28u, 0x71u, 0x08u, 0x3eu, 0x7bu, 0x0fu, 0xe5u,
            0x2du, 0xd7u, 0x86u, 0x68u, 0x88u, 0x2du, 0xf2u, 0x92u,
            0x38u, 0x44u, 0x9cu, 0x24u, 0xe3u, 0x3eu, 0x2eu, 0x5cu,
            0xafu, 0x16u, 0xafu, 0x6fu, 0x5du, 0x10u, 0x18u, 0x85u,
        };
        static const uint8_t kdf_sha512_expected[48] = {
            0x9au, 0x81u, 0x10u, 0x88u, 0x73u, 0x6bu, 0xa1u, 0x6du,
            0x9eu, 0xc6u, 0x5bu, 0xd6u, 0x97u, 0x69u, 0xf3u, 0x7fu,
            0x4du, 0xa2u, 0xcbu, 0xa8u, 0x60u, 0xeeu, 0x1du, 0x76u,
            0xeau, 0xeeu, 0x9du, 0x92u, 0xfdu, 0x2au, 0x07u, 0x03u,
            0x59u, 0xf9u, 0x0du, 0xb8u, 0x7cu, 0x1eu, 0x84u, 0x3fu,
            0xb3u, 0xedu, 0x1du, 0x7cu, 0xe5u, 0xc3u, 0x1eu, 0x5cu,
        };
        static const char other_info[] = "edge-kdf";
        test_keyctl_dh_params_t parameters;
        test_keyctl_kdf_params_t kdf;
        uint8_t shared_value[sizeof(prime_value) - 1u];
        uint8_t derived_value[sizeof(kdf_expected)];

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

        memset(&kdf, 0, sizeof(kdf));
        kdf.hash_name = (uint64_t)(uintptr_t)"sha256";
        kdf.other_info = (uint64_t)(uintptr_t)other_info;
        kdf.other_info_length = sizeof(other_info) - 1u;
        memset(derived_value, 0, sizeof(derived_value));
        arguments[1] = (uint64_t)(uintptr_t)derived_value;
        arguments[2] = sizeof(derived_value);
        arguments[3] = (uint64_t)(uintptr_t)&kdf;
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == (int64_t)sizeof(derived_value));
        assert(memcmp(derived_value, kdf_expected,
                      sizeof(derived_value)) == 0);
        kdf.hash_name = (uint64_t)(uintptr_t)"sha224";
        memset(derived_value, 0, sizeof(derived_value));
        arguments[2] = sizeof(kdf_sha224_expected);
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == (int64_t)sizeof(kdf_sha224_expected));
        assert(memcmp(derived_value, kdf_sha224_expected,
                      sizeof(kdf_sha224_expected)) == 0);
        kdf.hash_name = (uint64_t)(uintptr_t)"sha1";
        memset(derived_value, 0, sizeof(derived_value));
        arguments[2] = sizeof(kdf_sha1_expected);
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == (int64_t)sizeof(kdf_sha1_expected));
        assert(memcmp(derived_value, kdf_sha1_expected,
                      sizeof(kdf_sha1_expected)) == 0);
        kdf.hash_name = (uint64_t)(uintptr_t)"sha384";
        memset(derived_value, 0, sizeof(derived_value));
        arguments[2] = sizeof(kdf_sha384_expected);
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == (int64_t)sizeof(kdf_sha384_expected));
        assert(memcmp(derived_value, kdf_sha384_expected,
                      sizeof(kdf_sha384_expected)) == 0);
        kdf.hash_name = (uint64_t)(uintptr_t)"sha512";
        memset(derived_value, 0, sizeof(derived_value));
        arguments[2] = sizeof(kdf_sha512_expected);
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == (int64_t)sizeof(kdf_sha512_expected));
        assert(memcmp(derived_value, kdf_sha512_expected,
                      sizeof(kdf_sha512_expected)) == 0);
        kdf.spare[0] = 1u;
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_DH_COMPUTE,
                   arguments) == -EDGE_LINUX_EINVAL);
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

    {
        static const char constructed[] = "constructed-payload";
        int64_t requested;

        request_helper_mode = 1;
        request_helper_calls = 0;
        requested = kernel_keyring_request_key(
            &parent, &access, (uint64_t)(uintptr_t)"user",
            (uint64_t)(uintptr_t)"constructed-positive",
            (uint64_t)(uintptr_t)"unit-callout",
            EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
        assert(requested > 0 && request_helper_calls == 1);
        memset(output, 0, sizeof(output));
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = (uint64_t)requested;
        arguments[1] = (uint64_t)(uintptr_t)output;
        arguments[2] = sizeof(output);
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_READ,
                   arguments) == (int64_t)(sizeof(constructed) - 1u));
        assert(!memcmp(output, constructed, sizeof(constructed) - 1u));

        request_helper_mode = 2;
        assert(kernel_keyring_request_key(
                   &parent, &access, (uint64_t)(uintptr_t)"user",
                   (uint64_t)(uintptr_t)"constructed-negative",
                   (uint64_t)(uintptr_t)"unit-callout",
                   EDGE_LINUX_KEY_SPEC_SESSION_KEYRING) ==
               -EDGE_LINUX_ENOKEY);
        assert(request_helper_calls == 2);
        assert(kernel_keyring_request_key(
                   &parent, &access, (uint64_t)(uintptr_t)"user",
                   (uint64_t)(uintptr_t)"constructed-negative",
                   (uint64_t)(uintptr_t)"unit-callout",
                   EDGE_LINUX_KEY_SPEC_SESSION_KEYRING) ==
               -EDGE_LINUX_ENOKEY);
        assert(request_helper_calls == 2);

        request_helper_mode = 3;
        assert(kernel_keyring_request_key(
                   &parent, &access, (uint64_t)(uintptr_t)"user",
                   (uint64_t)(uintptr_t)"constructed-rejected",
                   (uint64_t)(uintptr_t)"unit-callout",
                   EDGE_LINUX_KEY_SPEC_SESSION_KEYRING) ==
               -EDGE_LINUX_EACCES);
        assert(request_helper_calls == 3);
    }

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
    assert((capabilities[0] & 8u) != 0u);
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
               arguments) == -EDGE_LINUX_EFAULT);

    {
        uint8_t rsa_certificate[90] = {0};
        uint8_t encrypted[64] = {0};
        uint8_t digest[32] = {0};
        uint8_t signature[64] = {0};
        uint8_t plaintext = 0x41u;
        test_keyctl_pkey_query_t query;
        test_keyctl_pkey_parameters_t parameters;
        int64_t asymmetric;

        rsa_certificate[0] = 0x30u;
        rsa_certificate[1] = 88u;
        rsa_certificate[2] = 0x06u;
        rsa_certificate[3] = 9u;
        rsa_certificate[4] = 0x2au;
        rsa_certificate[5] = 0x86u;
        rsa_certificate[6] = 0x48u;
        rsa_certificate[7] = 0x86u;
        rsa_certificate[8] = 0xf7u;
        rsa_certificate[9] = 0x0du;
        rsa_certificate[10] = 1u;
        rsa_certificate[11] = 1u;
        rsa_certificate[12] = 1u;
        rsa_certificate[13] = 0x03u;
        rsa_certificate[14] = 75u;
        rsa_certificate[15] = 0u;
        rsa_certificate[16] = 0x30u;
        rsa_certificate[17] = 72u;
        rsa_certificate[18] = 0x02u;
        rsa_certificate[19] = 65u;
        rsa_certificate[20] = 0u;
        memset(rsa_certificate + 21u, 0xa5u, 64u);
        rsa_certificate[84] = 0xb7u;
        rsa_certificate[85] = 0x02u;
        rsa_certificate[86] = 3u;
        rsa_certificate[87] = 1u;
        rsa_certificate[88] = 0u;
        rsa_certificate[89] = 1u;
        asymmetric = kernel_keyring_add_key(
            &parent, &access, (uint64_t)(uintptr_t)"asymmetric",
            (uint64_t)(uintptr_t)"unit-rsa",
            (uint64_t)(uintptr_t)rsa_certificate,
            sizeof(rsa_certificate), EDGE_LINUX_KEY_SPEC_SESSION_KEYRING);
        assert(asymmetric > 0);
        assert(kernel_keyring_add_key(
                   &parent, &access,
                   (uint64_t)(uintptr_t)"asymmetric", 0u,
                   (uint64_t)(uintptr_t)rsa_certificate,
                   sizeof(rsa_certificate),
                   EDGE_LINUX_KEY_SPEC_SESSION_KEYRING) > 0);

        memset(&query, 0xff, sizeof(query));
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = (uint64_t)(uint32_t)asymmetric;
        arguments[2] = (uint64_t)(uintptr_t)"enc=pkcs1 hash=sha256";
        arguments[3] = (uint64_t)(uintptr_t)&query;
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_PKEY_QUERY,
                   arguments) == 0);
        assert(query.supported_operations == 9u);
        assert(query.key_size == 512u);
        assert(query.maximum_data_size == 64u);
        for (uint32_t index = 0;
             index < sizeof(query.spare) / sizeof(query.spare[0]); ++index)
            assert(query.spare[index] == 0u);

        memset(&parameters, 0, sizeof(parameters));
        parameters.key_id = (int32_t)asymmetric;
        parameters.input_length = 1u;
        parameters.output_length = sizeof(encrypted);
        arguments[0] = (uint64_t)(uintptr_t)&parameters;
        arguments[1] = (uint64_t)(uintptr_t)"enc=raw";
        arguments[2] = (uint64_t)(uintptr_t)&plaintext;
        arguments[3] = (uint64_t)(uintptr_t)encrypted;
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_PKEY_ENCRYPT,
                   arguments) == (int64_t)sizeof(encrypted));

        parameters.input_length = sizeof(digest);
        parameters.output_length = sizeof(signature);
        arguments[1] =
            (uint64_t)(uintptr_t)"enc=pkcs1 hash=sha256";
        arguments[2] = (uint64_t)(uintptr_t)digest;
        arguments[3] = (uint64_t)(uintptr_t)signature;
        assert(kernel_keyring_keyctl(
                   &parent, &access, EDGE_LINUX_KEYCTL_PKEY_VERIFY,
                   arguments) == -EDGE_LINUX_EINVAL);
    }

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
