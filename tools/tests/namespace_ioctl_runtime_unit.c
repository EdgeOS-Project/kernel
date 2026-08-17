/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent namespace ioctl policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/namespace_runtime.h"

static int failures;
static int owner_lookup_status;
static int owner_lookup_calls;
static uint32_t owner_lookup_value;

uint64_t edge_namespace_clone_flag(edge_namespace_kind_t kind) {
    return UINT64_C(1) << (uint32_t)kind;
}

uint64_t edge_namespace_handle_inode(
    edge_namespace_kind_t kind, uint32_t id) {
    return UINT64_C(0x4e53000000000000) |
           ((uint64_t)(uint32_t)kind << 32) | id;
}

int edge_namespace_owner_uid(
    edge_namespace_kind_t kind, uint32_t id, uint32_t *uid_out) {
    (void)kind;
    (void)id;
    ++owner_lookup_calls;
    if (owner_lookup_status < 0) return owner_lookup_status;
    if (!uid_out) return -1;
    *uid_out = owner_lookup_value;
    return 0;
}

static void expect(int condition, const char *name) {
    if (condition) {
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s\n", name);
        ++failures;
    }
}

static void test_namespace_types(void) {
    kernel_namespace_descriptor_t descriptor;
    kernel_namespace_ioctl_output_t output;

    for (uint32_t kind = 0; kind < EDGE_NAMESPACE_KIND_COUNT; ++kind) {
        descriptor.kind = (edge_namespace_kind_t)kind;
        descriptor.id = kind + 7u;
        expect(kernel_namespace_ioctl_prepare(
                   &descriptor, KERNEL_NS_GET_NSTYPE, 0, &output) == 0,
               "NS_GET_NSTYPE accepts every namespace kind");
        expect(output.kind == KERNEL_NAMESPACE_IOCTL_IMMEDIATE &&
                   output.result == (int64_t)(UINT64_C(1) << kind),
               "NS_GET_NSTYPE returns the shared clone flag");
    }
}

static void test_namespace_identifiers(void) {
    kernel_namespace_descriptor_t descriptor = {
        .kind = EDGE_NAMESPACE_UTS,
        .id = 41u,
    };
    kernel_namespace_ioctl_output_t output;
    uint64_t expected = edge_namespace_handle_inode(
        descriptor.kind, descriptor.id);

    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_ID, 1, &output) == 0,
           "NS_GET_ID accepts a namespace descriptor");
    expect(output.kind == KERNEL_NAMESPACE_IOCTL_COPY_ID &&
               output.result == 0 && output.namespace_id == expected,
           "NS_GET_ID prepares the 64-bit namespace identifier");

    descriptor.kind = EDGE_NAMESPACE_MNT;
    descriptor.id = 73u;
    expected = edge_namespace_handle_inode(
        descriptor.kind, descriptor.id);
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_MNTNS_ID, 1, &output) == 0,
           "NS_GET_MNTNS_ID accepts a mount namespace");
    expect(output.kind == KERNEL_NAMESPACE_IOCTL_COPY_ID &&
               output.result == 0 && output.namespace_id == expected,
           "NS_GET_MNTNS_ID prepares the 64-bit mount identifier");

    descriptor.kind = EDGE_NAMESPACE_UTS;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_MNTNS_ID, 1, &output) ==
               -EDGE_LINUX_ENOTTY,
           "NS_GET_MNTNS_ID rejects a non-mount namespace");
}

static void test_owner_uid(void) {
    kernel_namespace_descriptor_t descriptor = {
        .kind = EDGE_NAMESPACE_USER,
        .id = 19u,
    };
    kernel_namespace_ioctl_output_t output;

    owner_lookup_status = 0;
    owner_lookup_value = 1007u;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_OWNER_UID, 1, &output) == 0,
           "NS_GET_OWNER_UID accepts a user namespace");
    expect(output.kind == KERNEL_NAMESPACE_IOCTL_COPY_OWNER_UID &&
               output.result == 0 &&
               output.owner_uid == owner_lookup_value,
           "NS_GET_OWNER_UID prepares the 32-bit owner uid");

    owner_lookup_status = -1;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_OWNER_UID, 1, &output) ==
               -EDGE_LINUX_EINVAL,
           "NS_GET_OWNER_UID rejects a missing owner record");
    owner_lookup_status = 0;

    descriptor.kind = EDGE_NAMESPACE_UTS;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_OWNER_UID, 1, &output) ==
               -EDGE_LINUX_ENOTTY,
           "NS_GET_OWNER_UID rejects a non-user namespace");
}

static void test_invalid_requests(void) {
    kernel_namespace_descriptor_t descriptor = {
        .kind = EDGE_NAMESPACE_UTS,
        .id = 1u,
    };
    kernel_namespace_ioctl_output_t output;

    expect(kernel_namespace_ioctl_prepare(
               0, KERNEL_NS_GET_ID, 1, &output) == -EDGE_LINUX_EINVAL,
           "namespace ioctl rejects a null descriptor");
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_ID, 1, 0) == -EDGE_LINUX_EINVAL,
           "namespace ioctl rejects a null output");
    descriptor.kind = (edge_namespace_kind_t)EDGE_NAMESPACE_KIND_COUNT;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_ID, 1, &output) ==
               -EDGE_LINUX_EINVAL,
           "namespace ioctl rejects an invalid namespace kind");
    descriptor.kind = EDGE_NAMESPACE_UTS;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_ID, 0, &output) ==
               -EDGE_LINUX_EFAULT,
           "NS_GET_ID rejects a null userspace output");
    descriptor.kind = EDGE_NAMESPACE_MNT;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_MNTNS_ID, 0, &output) ==
               -EDGE_LINUX_EFAULT,
           "NS_GET_MNTNS_ID rejects a null userspace output");
    descriptor.kind = EDGE_NAMESPACE_USER;
    owner_lookup_calls = 0;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, KERNEL_NS_GET_OWNER_UID, 0, &output) ==
               -EDGE_LINUX_EFAULT,
           "NS_GET_OWNER_UID rejects a null userspace output");
    expect(owner_lookup_calls == 0,
           "NS_GET_OWNER_UID validates output before owner lookup");
    descriptor.kind = EDGE_NAMESPACE_UTS;
    expect(kernel_namespace_ioctl_prepare(
               &descriptor, UINT32_C(0xffffffff), 1, &output) ==
               -EDGE_LINUX_ENOTTY,
           "namespace ioctl rejects an unsupported command");
}

int main(void) {
    test_namespace_types();
    test_namespace_identifiers();
    test_owner_uid();
    test_invalid_requests();
    printf("NAMESPACE_IOCTL_RUNTIME_%s failures=%d\n",
           failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
