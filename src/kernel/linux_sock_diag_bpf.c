/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Linux socket-diagnostic access to BPF socket-local storage. */

#include <stdint.h>

#include "kernel/bpf_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_sock_diag.h"

static int edge_sock_diag_bpf_map_info(
    int object_id, edge_linux_sock_diag_bpf_map_t *map) {
    kernel_bpf_map_info_t information;
    int status;

    if (!map) return -EDGE_LINUX_EINVAL;
    status = kernel_bpf_object_retain(object_id);
    if (status < 0) return status;
    status = kernel_bpf_map_info(object_id, &information);
    if (status < 0 || information.type != KERNEL_BPF_MAP_TYPE_SK_STORAGE) {
        kernel_bpf_object_release(object_id);
        return status < 0 ? status : -EDGE_LINUX_EINVAL;
    }
    map->object_id = object_id;
    map->user_id = information.id;
    map->value_size = information.value_size;
    return 0;
}

static int edge_sock_diag_bpf_map_from_descriptor(
    void *context, int32_t descriptor,
    edge_linux_sock_diag_bpf_map_t *map) {
    int object_id;

    (void)context;
    object_id = kernel_bpf_descriptor_object(
        descriptor, KERNEL_BPF_OBJECT_MAP);
    if (object_id < 0) return object_id;
    return edge_sock_diag_bpf_map_info(object_id, map);
}

static int edge_sock_diag_bpf_next_map(
    void *context, uint32_t *cursor,
    edge_linux_sock_diag_bpf_map_t *map) {
    uint32_t next_id;
    int object_id;
    int status;

    (void)context;
    if (!cursor || !map) return -EDGE_LINUX_EINVAL;
    next_id = *cursor;
    for (;;) {
        status = kernel_bpf_object_next_user_id(
            KERNEL_BPF_OBJECT_MAP, next_id, &next_id);
        if (status < 0) return status;
        object_id = kernel_bpf_object_from_user_id(
            KERNEL_BPF_OBJECT_MAP, next_id);
        if (object_id < 0) {
            *cursor = next_id;
            continue;
        }
        status = edge_sock_diag_bpf_map_info(object_id, map);
        *cursor = next_id;
        if (status == -EDGE_LINUX_EINVAL) continue;
        return status;
    }
}

static int edge_sock_diag_bpf_lookup(
    void *context, const edge_linux_sock_diag_bpf_map_t *map,
    uint64_t socket_identity, void *value) {
    (void)context;
    if (!map || !socket_identity || !value)
        return -EDGE_LINUX_ENOENT;
    return kernel_bpf_sk_storage_lookup(
        map->object_id, socket_identity, value, 0u);
}

static int edge_sock_diag_bpf_exists(
    void *context, const edge_linux_sock_diag_bpf_map_t *map,
    uint64_t socket_identity) {
    (void)context;
    if (!map || !socket_identity) return -EDGE_LINUX_ENOENT;
    return kernel_bpf_sk_storage_exists(
        map->object_id, socket_identity);
}

static void edge_sock_diag_bpf_release(
    void *context, const edge_linux_sock_diag_bpf_map_t *map) {
    (void)context;
    if (map && map->object_id >= 0)
        kernel_bpf_object_release(map->object_id);
}

const edge_linux_sock_diag_bpf_ops_t edge_linux_sock_diag_bpf_runtime_ops = {
    .map_from_descriptor = edge_sock_diag_bpf_map_from_descriptor,
    .next_map = edge_sock_diag_bpf_next_map,
    .lookup = edge_sock_diag_bpf_lookup,
    .exists = edge_sock_diag_bpf_exists,
    .release = edge_sock_diag_bpf_release,
    .context = 0,
};
