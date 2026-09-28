/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux key retention service interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_KEYRING_RUNTIME_H
#define EDGEOS_KERNEL_KEYRING_RUNTIME_H

#include <stdint.h>

#include "kernel/process_runtime.h"

#define EDGE_LINUX_KEY_SPEC_THREAD_KEYRING      (-1)
#define EDGE_LINUX_KEY_SPEC_PROCESS_KEYRING     (-2)
#define EDGE_LINUX_KEY_SPEC_SESSION_KEYRING     (-3)
#define EDGE_LINUX_KEY_SPEC_USER_KEYRING        (-4)
#define EDGE_LINUX_KEY_SPEC_USER_SESSION_KEYRING (-5)
#define EDGE_LINUX_KEY_SPEC_GROUP_KEYRING       (-6)
#define EDGE_LINUX_KEY_SPEC_REQKEY_AUTH_KEY     (-7)
#define EDGE_LINUX_KEY_SPEC_REQUESTOR_KEYRING   (-8)

#define EDGE_LINUX_KEY_REQKEY_DEFL_NO_CHANGE       (-1)
#define EDGE_LINUX_KEY_REQKEY_DEFL_DEFAULT          0
#define EDGE_LINUX_KEY_REQKEY_DEFL_THREAD_KEYRING   1
#define EDGE_LINUX_KEY_REQKEY_DEFL_PROCESS_KEYRING  2
#define EDGE_LINUX_KEY_REQKEY_DEFL_SESSION_KEYRING  3
#define EDGE_LINUX_KEY_REQKEY_DEFL_USER_KEYRING     4
#define EDGE_LINUX_KEY_REQKEY_DEFL_USER_SESSION_KEYRING 5
#define EDGE_LINUX_KEY_REQKEY_DEFL_GROUP_KEYRING    6
#define EDGE_LINUX_KEY_REQKEY_DEFL_REQUESTOR_KEYRING 7

enum edge_linux_keyctl_command {
    EDGE_LINUX_KEYCTL_GET_KEYRING_ID = 0,
    EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING = 1,
    EDGE_LINUX_KEYCTL_UPDATE = 2,
    EDGE_LINUX_KEYCTL_REVOKE = 3,
    EDGE_LINUX_KEYCTL_CHOWN = 4,
    EDGE_LINUX_KEYCTL_SETPERM = 5,
    EDGE_LINUX_KEYCTL_DESCRIBE = 6,
    EDGE_LINUX_KEYCTL_CLEAR = 7,
    EDGE_LINUX_KEYCTL_LINK = 8,
    EDGE_LINUX_KEYCTL_UNLINK = 9,
    EDGE_LINUX_KEYCTL_SEARCH = 10,
    EDGE_LINUX_KEYCTL_READ = 11,
    EDGE_LINUX_KEYCTL_INSTANTIATE = 12,
    EDGE_LINUX_KEYCTL_NEGATE = 13,
    EDGE_LINUX_KEYCTL_SET_REQKEY_KEYRING = 14,
    EDGE_LINUX_KEYCTL_SET_TIMEOUT = 15,
    EDGE_LINUX_KEYCTL_ASSUME_AUTHORITY = 16,
    EDGE_LINUX_KEYCTL_GET_SECURITY = 17,
    EDGE_LINUX_KEYCTL_SESSION_TO_PARENT = 18,
    EDGE_LINUX_KEYCTL_REJECT = 19,
    EDGE_LINUX_KEYCTL_INSTANTIATE_IOV = 20,
    EDGE_LINUX_KEYCTL_INVALIDATE = 21,
    EDGE_LINUX_KEYCTL_GET_PERSISTENT = 22,
    EDGE_LINUX_KEYCTL_DH_COMPUTE = 23,
    EDGE_LINUX_KEYCTL_PKEY_QUERY = 24,
    EDGE_LINUX_KEYCTL_PKEY_ENCRYPT = 25,
    EDGE_LINUX_KEYCTL_PKEY_DECRYPT = 26,
    EDGE_LINUX_KEYCTL_PKEY_SIGN = 27,
    EDGE_LINUX_KEYCTL_PKEY_VERIFY = 28,
    EDGE_LINUX_KEYCTL_RESTRICT_KEYRING = 29,
    EDGE_LINUX_KEYCTL_MOVE = 30,
    EDGE_LINUX_KEYCTL_CAPABILITIES = 31,
    EDGE_LINUX_KEYCTL_WATCH_KEY = 32,
};

#define EDGE_LINUX_KEYCTL_MOVE_EXCL 0x00000001u

#define EDGE_LINUX_KEY_POS_VIEW    0x01000000u
#define EDGE_LINUX_KEY_POS_READ    0x02000000u
#define EDGE_LINUX_KEY_POS_WRITE   0x04000000u
#define EDGE_LINUX_KEY_POS_SEARCH  0x08000000u
#define EDGE_LINUX_KEY_POS_LINK    0x10000000u
#define EDGE_LINUX_KEY_POS_SETATTR 0x20000000u
#define EDGE_LINUX_KEY_POS_ALL     0x3f000000u
#define EDGE_LINUX_KEY_USR_VIEW    0x00010000u
#define EDGE_LINUX_KEY_USR_READ    0x00020000u
#define EDGE_LINUX_KEY_USR_WRITE   0x00040000u
#define EDGE_LINUX_KEY_USR_SEARCH  0x00080000u
#define EDGE_LINUX_KEY_USR_LINK    0x00100000u
#define EDGE_LINUX_KEY_USR_SETATTR 0x00200000u
#define EDGE_LINUX_KEY_USR_ALL     0x003f0000u
#define EDGE_LINUX_KEY_GRP_ALL     0x00003f00u
#define EDGE_LINUX_KEY_OTH_ALL     0x0000003fu
#define EDGE_LINUX_KEY_PERM_ALL    0x3f3f3f3fu

typedef int (*kernel_keyring_copy_from_user_fn)(
    void *context, void *destination, uint64_t source, uint64_t length);
typedef int (*kernel_keyring_copy_to_user_fn)(
    void *context, uint64_t destination, const void *source, uint64_t length);
typedef int (*kernel_keyring_request_helper_fn)(
    void *context, int32_t authorization, int32_t target,
    uint32_t uid, uint32_t gid, int32_t thread_keyring,
    int32_t process_keyring, int32_t session_keyring);

typedef struct kernel_keyring_user_access {
    kernel_keyring_copy_from_user_fn copy_from_user;
    kernel_keyring_copy_to_user_fn copy_to_user;
    void *context;
    uint32_t iovec_pointer_size;
    uint32_t keyctl_kdf_pointer_size;
    kernel_keyring_request_helper_fn invoke_request_helper;
} kernel_keyring_user_access_t;

int64_t kernel_keyring_add_key(
    const kernel_linux_identity_t *identity,
    const kernel_keyring_user_access_t *access,
    uint64_t type, uint64_t description, uint64_t payload,
    uint64_t payload_length, int32_t keyring);
int64_t kernel_keyring_request_key(
    const kernel_linux_identity_t *identity,
    const kernel_keyring_user_access_t *access,
    uint64_t type, uint64_t description, uint64_t callout,
    int32_t destination_keyring);
int64_t kernel_keyring_keyctl(
    const kernel_linux_identity_t *identity,
    const kernel_keyring_user_access_t *access,
    uint32_t command, const uint64_t arguments[4]);
int kernel_keyring_request_authority_grant(
    const kernel_linux_identity_t *identity, int32_t authorization);
void kernel_keyring_task_exit(int32_t global_tid, int32_t global_tgid,
                              int whole_thread_group);

#endif
