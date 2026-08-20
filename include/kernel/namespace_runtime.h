/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS namespace syscall runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_NAMESPACE_RUNTIME_H
#define EDGEOS_KERNEL_NAMESPACE_RUNTIME_H

#include <stdint.h>

#include "kernel/namespaces.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"

#define KERNEL_CLONE_FS    EDGE_LINUX_CLONE_FS
#define KERNEL_CLONE_FILES EDGE_LINUX_CLONE_FILES

#define KERNEL_NS_GET_NSTYPE    0xb703u
#define KERNEL_NS_GET_OWNER_UID 0xb704u
#define KERNEL_NS_GET_MNTNS_ID  0x8008b705u
#define KERNEL_NS_GET_ID        0x8008b70du

typedef struct kernel_namespace_descriptor {
    edge_namespace_kind_t kind;
    uint32_t id;
} kernel_namespace_descriptor_t;

typedef enum kernel_namespace_ioctl_output_kind {
    KERNEL_NAMESPACE_IOCTL_IMMEDIATE = 0,
    KERNEL_NAMESPACE_IOCTL_COPY_ID,
    KERNEL_NAMESPACE_IOCTL_COPY_OWNER_UID
} kernel_namespace_ioctl_output_kind_t;

typedef struct kernel_namespace_ioctl_output {
    kernel_namespace_ioctl_output_kind_t kind;
    int64_t result;
    uint64_t namespace_id;
    uint32_t owner_uid;
} kernel_namespace_ioctl_output_t;

static inline int kernel_namespace_ioctl_prepare(
    const kernel_namespace_descriptor_t *descriptor, uint32_t command,
    int has_user_output, kernel_namespace_ioctl_output_t *output) {
    if (!descriptor || !output ||
        (uint32_t)descriptor->kind >= EDGE_NAMESPACE_KIND_COUNT)
        return -EDGE_LINUX_EINVAL;

    output->kind = KERNEL_NAMESPACE_IOCTL_IMMEDIATE;
    output->result = 0;
    output->namespace_id = 0;
    output->owner_uid = 0;
    if (command == KERNEL_NS_GET_NSTYPE) {
        output->result =
            (int64_t)edge_namespace_clone_flag(descriptor->kind);
        return 0;
    }
    if (command == KERNEL_NS_GET_ID ||
        (command == KERNEL_NS_GET_MNTNS_ID &&
         descriptor->kind == EDGE_NAMESPACE_MNT)) {
        if (!has_user_output) return -EDGE_LINUX_EFAULT;
        output->kind = KERNEL_NAMESPACE_IOCTL_COPY_ID;
        output->namespace_id = edge_namespace_list_id(
            descriptor->kind, descriptor->id);
        if (!output->namespace_id) return -EDGE_LINUX_EINVAL;
        return 0;
    }
    if (command == KERNEL_NS_GET_OWNER_UID &&
        descriptor->kind == EDGE_NAMESPACE_USER) {
        if (!has_user_output) return -EDGE_LINUX_EFAULT;
        if (edge_namespace_owner_uid(
                descriptor->kind, descriptor->id,
                &output->owner_uid) < 0)
            return -EDGE_LINUX_EINVAL;
        output->kind = KERNEL_NAMESPACE_IOCTL_COPY_OWNER_UID;
        return 0;
    }
    return -EDGE_LINUX_ENOTTY;
}

typedef struct kernel_namespace_runtime_state {
    uint32_t user_namespace_id;
    uint32_t thread_count;
    uint8_t filesystem_context_shared;
} kernel_namespace_runtime_state_t;

edge_namespace_set_t *kernel_arch_current_namespace_set(void);
void kernel_arch_current_namespace_committed(
    const edge_namespace_set_t *namespaces);
/*
 * An open non-namespace descriptor returns ENOTTY so ioctl can fall through
 * to its architecture backend. Invalid descriptors and malformed namespace
 * descriptors remain distinguishable as EBADF and EINVAL.
 */
int kernel_namespace_descriptor_get(
    int32_t descriptor, kernel_namespace_descriptor_t *information);
int kernel_user_namespace_capabilities_grant(int32_t tid);
int arch_namespace_descriptor_get(
    int32_t descriptor, kernel_namespace_descriptor_t *information);
int kernel_current_namespace_state(
    kernel_namespace_runtime_state_t *state);
int kernel_current_namespace_join(edge_namespace_kind_t kind, uint32_t id);
int kernel_current_namespaces_unshare(uint64_t flags,
                                      uint32_t owner_uid,
                                      uint32_t owner_gid);

#endif
