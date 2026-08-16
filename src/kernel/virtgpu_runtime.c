/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent Linux virtgpu render ABI.
 *
 * The public layouts and ioctl numbers follow the MIT-licensed virtgpu DRM
 * UAPI. Device transport is supplied by a registered EdgeOS backend.
 */

#include <stddef.h>
#include <stdint.h>

#include "kernel/anonymous_fd.h"
#include "kernel/drm_runtime.h"
#include "kernel/fd_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/virtgpu_runtime.h"
#include "mm/arch_vm.h"
#include "string.h"

#define EDGE_VIRTGPU_IOCTL_VERSION          0xc0406400u
#define EDGE_VIRTGPU_IOCTL_GEM_CLOSE        0x40086409u
#define EDGE_VIRTGPU_IOCTL_GET_CAP          0xc010640cu
#define EDGE_VIRTGPU_IOCTL_PRIME_HANDLE_TO_FD 0xc00c642du
#define EDGE_VIRTGPU_IOCTL_PRIME_FD_TO_HANDLE 0xc00c642eu
#define EDGE_VIRTGPU_IOCTL_MAP              0xc0106441u
#define EDGE_VIRTGPU_IOCTL_EXECBUFFER       0xc0406442u
#define EDGE_VIRTGPU_IOCTL_GETPARAM         0xc0106443u
#define EDGE_VIRTGPU_IOCTL_RESOURCE_CREATE  0xc0386444u
#define EDGE_VIRTGPU_IOCTL_RESOURCE_INFO    0xc0106445u
#define EDGE_VIRTGPU_IOCTL_TRANSFER_FROM    0xc02c6446u
#define EDGE_VIRTGPU_IOCTL_TRANSFER_TO      0xc02c6447u
#define EDGE_VIRTGPU_IOCTL_WAIT             0xc0086448u
#define EDGE_VIRTGPU_IOCTL_GET_CAPS         0xc0186449u
#define EDGE_VIRTGPU_IOCTL_CREATE_BLOB      0xc030644au
#define EDGE_VIRTGPU_IOCTL_CONTEXT_INIT     0xc010644bu

#define EDGE_VIRTGPU_PARAM_3D_FEATURES          1u
#define EDGE_VIRTGPU_PARAM_CAPSET_QUERY_FIX     2u
#define EDGE_VIRTGPU_PARAM_RESOURCE_BLOB        3u
#define EDGE_VIRTGPU_PARAM_HOST_VISIBLE         4u
#define EDGE_VIRTGPU_PARAM_CROSS_DEVICE         5u
#define EDGE_VIRTGPU_PARAM_CONTEXT_INIT         6u
#define EDGE_VIRTGPU_PARAM_SUPPORTED_CAPSETS    7u
#define EDGE_VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME  8u

#define EDGE_VIRTGPU_CONTEXT_PARAM_CAPSET_ID       1u
#define EDGE_VIRTGPU_CONTEXT_PARAM_NUM_RINGS       2u
#define EDGE_VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK 3u
#define EDGE_VIRTGPU_CONTEXT_PARAM_DEBUG_NAME      4u

#define EDGE_VIRTGPU_EXECBUF_FENCE_FD_IN  0x01u
#define EDGE_VIRTGPU_EXECBUF_FENCE_FD_OUT 0x02u
#define EDGE_VIRTGPU_EXECBUF_RING_IDX     0x04u
#define EDGE_VIRTGPU_EXECBUF_FLAGS        0x07u
#define EDGE_VIRTGPU_WAIT_NOWAIT          0x01u
#define EDGE_VIRTGPU_PRIME_RDWR           0x00000002u
#define EDGE_VIRTGPU_PRIME_CLOEXEC        0x00080000u
#define EDGE_VIRTGPU_PRIME_FLAGS          \
    (EDGE_VIRTGPU_PRIME_RDWR | EDGE_VIRTGPU_PRIME_CLOEXEC)

#define EDGE_VIRTGPU_PAGE_SIZE          4096u
#define EDGE_VIRTGPU_CLIENT_COUNT       64u
#define EDGE_VIRTGPU_RESOURCE_COUNT     4096u
#define EDGE_VIRTGPU_EXEC_HANDLE_COUNT  256u
#define EDGE_VIRTGPU_CONTEXT_PARAM_COUNT 16u
#define EDGE_VIRTGPU_MAX_RESOURCE_SIZE  (256ull * 1024ull * 1024ull)
#define EDGE_VIRTGPU_MAX_COMMAND_SIZE   (4u * 1024u * 1024u)
#define EDGE_VIRTGPU_MAX_CAPSET_SIZE    (256u * 1024u)
#define EDGE_VIRTGPU_MAP_BASE           0x100000000ull

typedef struct {
    int32_t version_major;
    int32_t version_minor;
    int32_t version_patchlevel;
    uint32_t pad;
    uint64_t name_len;
    uint64_t name;
    uint64_t date_len;
    uint64_t date;
    uint64_t desc_len;
    uint64_t desc;
} edge_virtgpu_version_t;

typedef struct {
    uint64_t capability;
    uint64_t value;
} edge_virtgpu_get_cap_t;

typedef struct {
    uint32_t handle;
    uint32_t pad;
} edge_virtgpu_gem_close_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    int32_t fd;
} edge_virtgpu_prime_handle_t;

typedef struct {
    uint64_t offset;
    uint32_t handle;
    uint32_t pad;
} edge_virtgpu_map_t;

typedef struct {
    uint32_t flags;
    uint32_t size;
    uint64_t command;
    uint64_t bo_handles;
    uint32_t num_bo_handles;
    int32_t fence_fd;
    uint32_t ring_idx;
    uint32_t syncobj_stride;
    uint32_t num_in_syncobjs;
    uint32_t num_out_syncobjs;
    uint64_t in_syncobjs;
    uint64_t out_syncobjs;
} edge_virtgpu_execbuffer_t;

typedef struct {
    uint64_t param;
    uint64_t value;
} edge_virtgpu_getparam_t;

typedef struct {
    uint32_t target;
    uint32_t format;
    uint32_t bind;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
    uint32_t array_size;
    uint32_t last_level;
    uint32_t nr_samples;
    uint32_t flags;
    uint32_t bo_handle;
    uint32_t res_handle;
    uint32_t size;
    uint32_t stride;
} edge_virtgpu_resource_create_uapi_t;

typedef struct {
    uint32_t bo_handle;
    uint32_t res_handle;
    uint32_t size;
    uint32_t blob_mem;
} edge_virtgpu_resource_info_t;

typedef struct {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
} edge_virtgpu_box_t;

typedef struct {
    uint32_t bo_handle;
    edge_virtgpu_box_t box;
    uint32_t level;
    uint32_t offset;
    uint32_t stride;
    uint32_t layer_stride;
} edge_virtgpu_transfer_uapi_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
} edge_virtgpu_wait_t;

typedef struct {
    uint32_t cap_set_id;
    uint32_t cap_set_version;
    uint64_t address;
    uint32_t size;
    uint32_t pad;
} edge_virtgpu_get_caps_t;

typedef struct {
    uint64_t param;
    uint64_t value;
} edge_virtgpu_context_param_t;

typedef struct {
    uint32_t num_params;
    uint32_t pad;
    uint64_t params;
} edge_virtgpu_context_init_t;

typedef struct {
    uint8_t used;
    uint8_t context_created;
    uint8_t file_released;
    uint8_t pad;
    uint64_t identity;
    uint32_t context_id;
    uint32_t capset_id;
    char debug_name[64];
} edge_virtgpu_client_t;

typedef struct {
    uint8_t used;
    uint8_t handle_open;
    uint16_t framebuffer_refs;
    uint32_t prime_refs;
    uint32_t alias_refs;
    int32_t backing_object_id;
    uint64_t owner;
    uint32_t context_id;
    uint32_t bo_handle;
    uint32_t resource_id;
    uint32_t width;
    uint32_t height;
    uint32_t page_count;
    uint32_t size;
    uint32_t stride;
    uint32_t blob_mem;
    uint64_t map_offset;
    uint8_t *storage;
} edge_virtgpu_resource_t;

_Static_assert(sizeof(edge_virtgpu_version_t) == 64,
               "Linux DRM version layout mismatch");
_Static_assert(sizeof(edge_virtgpu_execbuffer_t) == 64,
               "Linux virtgpu execbuffer layout mismatch");
_Static_assert(sizeof(edge_virtgpu_resource_create_uapi_t) == 56,
               "Linux virtgpu resource create layout mismatch");
_Static_assert(sizeof(edge_virtgpu_transfer_uapi_t) == 44,
               "Linux virtgpu transfer layout mismatch");
_Static_assert(sizeof(edge_virtgpu_get_caps_t) == 24,
               "Linux virtgpu capset layout mismatch");
_Static_assert(sizeof(edge_virtgpu_prime_handle_t) == 12,
               "Linux DRM PRIME handle layout mismatch");

static edge_virtgpu_backend_t g_edge_virtgpu_backend;
static edge_virtgpu_client_t
    g_edge_virtgpu_clients[EDGE_VIRTGPU_CLIENT_COUNT];
static edge_virtgpu_resource_t
    g_edge_virtgpu_resources[EDGE_VIRTGPU_RESOURCE_COUNT];
static volatile unsigned int g_edge_virtgpu_guard;
static uint32_t g_edge_virtgpu_next_context = 1u;
static uint32_t g_edge_virtgpu_next_handle = 1u;
static uint32_t g_edge_virtgpu_next_resource = 2u;
static uint64_t g_edge_virtgpu_next_map = EDGE_VIRTGPU_MAP_BASE;

static void edge_virtgpu_relax(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void edge_virtgpu_lock(void) {
    while (__atomic_test_and_set(
               &g_edge_virtgpu_guard, __ATOMIC_ACQUIRE))
        edge_virtgpu_relax();
}

static void edge_virtgpu_unlock(void) {
    __atomic_clear(&g_edge_virtgpu_guard, __ATOMIC_RELEASE);
}

static uint64_t edge_virtgpu_align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static int edge_virtgpu_copy_from(
    const kernel_ioctl_request_t *request, void *destination,
    uint64_t source, uint64_t length) {
    if (!request || !request->copy_from_user || (!source && length))
        return -1;
    return request->copy_from_user(
        request->copy_context, destination, source, length);
}

static int edge_virtgpu_copy_to(
    const kernel_ioctl_request_t *request, uint64_t destination,
    const void *source, uint64_t length) {
    if (!request || !request->copy_to_user || (!destination && length))
        return -1;
    return request->copy_to_user(
        request->copy_context, destination, source, length);
}

static int edge_virtgpu_copy_string(
    const kernel_ioctl_request_t *request, uint64_t destination,
    uint64_t capacity, const char *source) {
    uint64_t length = 0;
    uint64_t count;

    while (source && source[length]) length++;
    count = capacity < length ? capacity : length;
    if (!count) return 0;
    return edge_virtgpu_copy_to(request, destination, source, count);
}

static edge_virtgpu_client_t *edge_virtgpu_client(
    uint64_t identity, int create) {
    edge_virtgpu_client_t *available = 0;

    for (uint32_t index = 0; index < EDGE_VIRTGPU_CLIENT_COUNT; ++index) {
        edge_virtgpu_client_t *client = &g_edge_virtgpu_clients[index];
        if (client->used && client->identity == identity) return client;
        if (!client->used && !available) available = client;
    }
    if (!create || !available) return 0;
    memset(available, 0, sizeof(*available));
    available->used = 1u;
    available->identity = identity;
    available->context_id = g_edge_virtgpu_next_context++;
    if (!available->context_id)
        available->context_id = g_edge_virtgpu_next_context++;
    available->capset_id =
        (g_edge_virtgpu_backend.info.supported_capsets & (1ull << 2)) ?
            2u : 1u;
    memcpy(available->debug_name, "edgeos-virtgpu", 15u);
    return available;
}

static edge_virtgpu_resource_t *edge_virtgpu_resource_record(
    uint64_t owner, uint32_t handle) {
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index) {
        edge_virtgpu_resource_t *resource =
            &g_edge_virtgpu_resources[index];
        if (resource->used && resource->owner == owner &&
            resource->bo_handle == handle)
            return resource;
    }
    return 0;
}

static edge_virtgpu_resource_t *edge_virtgpu_prime_resource(
    int32_t object_id) {
    uint32_t index;

    if (object_id <= 0) return 0;
    index = (uint32_t)object_id - 1u;
    if (index >= EDGE_VIRTGPU_RESOURCE_COUNT ||
        !g_edge_virtgpu_resources[index].used)
        return 0;
    return &g_edge_virtgpu_resources[index];
}

static edge_virtgpu_resource_t *edge_virtgpu_resource_backing(
    edge_virtgpu_resource_t *resource) {
    if (!resource || !resource->used) return 0;
    if (!resource->backing_object_id) return resource;
    resource = edge_virtgpu_prime_resource(
        resource->backing_object_id);
    return resource && !resource->backing_object_id ? resource : 0;
}

static edge_virtgpu_resource_t *edge_virtgpu_resource_handle(
    uint64_t owner, uint32_t handle) {
    edge_virtgpu_resource_t *resource =
        edge_virtgpu_resource_record(owner, handle);

    return resource && resource->handle_open ? resource : 0;
}

static edge_virtgpu_resource_t *edge_virtgpu_resource(
    uint64_t owner, uint32_t handle) {
    return edge_virtgpu_resource_backing(
        edge_virtgpu_resource_handle(owner, handle));
}

static int32_t edge_virtgpu_prime_object_id(
    const edge_virtgpu_resource_t *resource) {
    uintptr_t index;

    if (!resource || resource < g_edge_virtgpu_resources ||
        resource >=
            g_edge_virtgpu_resources + EDGE_VIRTGPU_RESOURCE_COUNT)
        return -1;
    index = (uintptr_t)(resource - g_edge_virtgpu_resources);
    return (int32_t)(index + 1u);
}

static int edge_virtgpu_context_ensure(edge_virtgpu_client_t *client) {
    if (!client) return -EDGE_LINUX_EINVAL;
    if (client->context_created) return 0;
    if (!g_edge_virtgpu_backend.operations.context_create ||
        g_edge_virtgpu_backend.operations.context_create(
            g_edge_virtgpu_backend.context, client->context_id,
            client->capset_id, client->debug_name) < 0)
        return -EDGE_LINUX_EIO;
    client->context_created = 1u;
    return 0;
}

static void edge_virtgpu_client_maybe_release(
    edge_virtgpu_client_t *client) {
    if (!client || !client->used || !client->file_released) return;
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index)
        if (g_edge_virtgpu_resources[index].used &&
            g_edge_virtgpu_resources[index].context_id ==
                client->context_id)
            return;
    if (client->context_created &&
        g_edge_virtgpu_backend.operations.context_destroy)
        (void)g_edge_virtgpu_backend.operations.context_destroy(
            g_edge_virtgpu_backend.context, client->context_id);
    memset(client, 0, sizeof(*client));
}

static void edge_virtgpu_storage_release(
    void *storage, uint32_t page_count) {
    for (uint32_t page = 0; storage && page < page_count; ++page)
        arch_vm_free_page(
            (uint8_t *)storage +
            (uint64_t)page * EDGE_VIRTGPU_PAGE_SIZE);
}

static void edge_virtgpu_resource_release(
    edge_virtgpu_resource_t *resource) {
    edge_virtgpu_client_t *client = 0;
    uint8_t *storage;
    uint32_t context_id;
    uint32_t pages;

    if (!resource || !resource->used || resource->backing_object_id)
        return;
    context_id = resource->context_id;
    for (uint32_t index = 0; index < EDGE_VIRTGPU_CLIENT_COUNT; ++index)
        if (g_edge_virtgpu_clients[index].used &&
            g_edge_virtgpu_clients[index].context_id == context_id) {
            client = &g_edge_virtgpu_clients[index];
            break;
        }
    if (g_edge_virtgpu_backend.operations.resource_destroy)
        (void)g_edge_virtgpu_backend.operations.resource_destroy(
            g_edge_virtgpu_backend.context, context_id,
            resource->resource_id);
    storage = resource->storage;
    pages = resource->page_count;
    memset(resource, 0, sizeof(*resource));
    edge_virtgpu_storage_release(storage, pages);
    edge_virtgpu_client_maybe_release(client);
}

static void edge_virtgpu_resource_maybe_release(
    edge_virtgpu_resource_t *resource) {
    edge_virtgpu_resource_t *backing;

    if (!resource || !resource->used || resource->handle_open ||
        resource->framebuffer_refs)
        return;
    if (resource->backing_object_id) {
        backing = edge_virtgpu_prime_resource(
            resource->backing_object_id);
        if (backing && resource->context_id &&
            g_edge_virtgpu_backend.operations.resource_detach)
            (void)g_edge_virtgpu_backend.operations.resource_detach(
                g_edge_virtgpu_backend.context, resource->context_id,
                backing->resource_id);
        memset(resource, 0, sizeof(*resource));
        if (backing && backing->alias_refs) {
            backing->alias_refs--;
            edge_virtgpu_resource_maybe_release(backing);
        }
        return;
    }
    if (!resource->prime_refs && !resource->alias_refs)
        edge_virtgpu_resource_release(resource);
}

static int64_t edge_virtgpu_ioctl_version(
    const kernel_ioctl_request_t *request) {
    static const char name[] = "virtio_gpu";
    static const char date[] = "20260729";
    static const char description[] = "EdgeOS VirtIO GPU";
    edge_virtgpu_version_t version;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &version, request->argument, sizeof(version)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (edge_virtgpu_copy_string(
            request, version.name, version.name_len, name) < 0 ||
        edge_virtgpu_copy_string(
            request, version.date, version.date_len, date) < 0 ||
        edge_virtgpu_copy_string(
            request, version.desc, version.desc_len, description) < 0)
        return -EDGE_LINUX_EFAULT;
    version.version_major = 0;
    version.version_minor = 0;
    version.version_patchlevel = 0;
    version.name_len = sizeof(name) - 1u;
    version.date_len = sizeof(date) - 1u;
    version.desc_len = sizeof(description) - 1u;
    return edge_virtgpu_copy_to(
               request, request->argument, &version, sizeof(version)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_ioctl_get_cap(
    const kernel_ioctl_request_t *request) {
    edge_virtgpu_get_cap_t capability;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &capability, request->argument,
            sizeof(capability)) < 0)
        return -EDGE_LINUX_EFAULT;
    switch (capability.capability) {
        case EDGE_DRM_CAP_PRIME:
            capability.value = edge_virtgpu_framebuffer_available() ?
                EDGE_DRM_PRIME_CAP_IMPORT |
                    EDGE_DRM_PRIME_CAP_EXPORT : 0u;
            break;
        case EDGE_DRM_CAP_TIMESTAMP_MONOTONIC:
        case EDGE_DRM_CAP_CRTC_IN_VBLANK_EVENT:
            capability.value = 1u;
            break;
        case EDGE_DRM_CAP_SYNCOBJ:
        case EDGE_DRM_CAP_SYNCOBJ_TIMELINE:
            capability.value = 0u;
            break;
        default:
            return -EDGE_LINUX_EINVAL;
    }
    return edge_virtgpu_copy_to(
               request, request->argument, &capability,
               sizeof(capability)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_ioctl_getparam(
    const kernel_ioctl_request_t *request) {
    edge_virtgpu_getparam_t parameter;
    uint64_t value;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &parameter, request->argument,
            sizeof(parameter)) < 0)
        return -EDGE_LINUX_EFAULT;
    switch (parameter.param) {
        case EDGE_VIRTGPU_PARAM_3D_FEATURES:
            value = !!(g_edge_virtgpu_backend.info.flags &
                       EDGE_VIRTGPU_BACKEND_VIRGL);
            break;
        case EDGE_VIRTGPU_PARAM_CAPSET_QUERY_FIX:
            value = !!(g_edge_virtgpu_backend.info.flags &
                       EDGE_VIRTGPU_BACKEND_CAPSET_QUERY_FIX);
            break;
        case EDGE_VIRTGPU_PARAM_RESOURCE_BLOB:
            value = !!(g_edge_virtgpu_backend.info.flags &
                       EDGE_VIRTGPU_BACKEND_RESOURCE_BLOB);
            break;
        case EDGE_VIRTGPU_PARAM_HOST_VISIBLE:
            value = !!(g_edge_virtgpu_backend.info.flags &
                       EDGE_VIRTGPU_BACKEND_HOST_VISIBLE);
            break;
        case EDGE_VIRTGPU_PARAM_CROSS_DEVICE:
        case EDGE_VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME:
            value = 0u;
            break;
        case EDGE_VIRTGPU_PARAM_CONTEXT_INIT:
            value = !!(g_edge_virtgpu_backend.info.flags &
                       EDGE_VIRTGPU_BACKEND_CONTEXT_INIT);
            break;
        case EDGE_VIRTGPU_PARAM_SUPPORTED_CAPSETS:
            value = g_edge_virtgpu_backend.info.supported_capsets;
            break;
        default:
            return -EDGE_LINUX_EINVAL;
    }
    return !parameter.value ||
           edge_virtgpu_copy_to(
               request, parameter.value, &value, sizeof(value)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_ioctl_resource_create(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_resource_create_uapi_t command;
    edge_virtgpu_resource_create_t create;
    edge_virtgpu_resource_t *resource = 0;
    edge_virtgpu_client_t *client;
    uint64_t allocation_size;
    uint64_t resource_size;
    uint32_t page_count;
    uint8_t *storage;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    resource_size = command.size ? command.size : EDGE_VIRTGPU_PAGE_SIZE;
    if (command.bo_handle || !command.width || !command.height ||
        !command.depth || !command.array_size ||
        resource_size > EDGE_VIRTGPU_MAX_RESOURCE_SIZE)
        return -EDGE_LINUX_EINVAL;
    page_count =
        (resource_size + EDGE_VIRTGPU_PAGE_SIZE - 1u) /
        EDGE_VIRTGPU_PAGE_SIZE;
    allocation_size = (uint64_t)page_count * EDGE_VIRTGPU_PAGE_SIZE;
    storage = arch_vm_alloc_pages(page_count);
    if (!storage) return -EDGE_LINUX_ENOMEM;

    edge_virtgpu_lock();
    client = edge_virtgpu_client(identity, 1);
    if (!client) {
        result = -EDGE_LINUX_ENOSPC;
        goto fail;
    }
    result = edge_virtgpu_context_ensure(client);
    if (result < 0) goto fail;
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index)
        if (!g_edge_virtgpu_resources[index].used) {
            resource = &g_edge_virtgpu_resources[index];
            break;
        }
    if (!resource) {
        result = -EDGE_LINUX_ENOSPC;
        goto fail;
    }
    memset(&create, 0, sizeof(create));
    create.target = command.target;
    create.format = command.format;
    create.bind = command.bind;
    create.width = command.width;
    create.height = command.height;
    create.depth = command.depth;
    create.array_size = command.array_size;
    create.last_level = command.last_level;
    create.nr_samples = command.nr_samples;
    create.flags = command.flags;
    create.size = resource_size;
    create.stride = command.stride;

    memset(resource, 0, sizeof(*resource));
    resource->used = 1u;
    resource->handle_open = 1u;
    resource->owner = identity;
    resource->context_id = client->context_id;
    resource->bo_handle = g_edge_virtgpu_next_handle++;
    if (!resource->bo_handle)
        resource->bo_handle = g_edge_virtgpu_next_handle++;
    resource->resource_id = g_edge_virtgpu_next_resource++;
    if (resource->resource_id < 2u)
        resource->resource_id = g_edge_virtgpu_next_resource = 2u;
    resource->page_count = page_count;
    resource->width = command.width;
    resource->height = command.height;
    resource->size = resource_size;
    resource->stride = command.stride;
    resource->storage = storage;
    resource->map_offset = g_edge_virtgpu_next_map;
    g_edge_virtgpu_next_map = edge_virtgpu_align_up(
        g_edge_virtgpu_next_map + allocation_size,
        EDGE_VIRTGPU_PAGE_SIZE);
    if (!g_edge_virtgpu_backend.operations.resource_create ||
        g_edge_virtgpu_backend.operations.resource_create(
            g_edge_virtgpu_backend.context, client->context_id,
            resource->resource_id, &create, storage, allocation_size) < 0) {
        memset(resource, 0, sizeof(*resource));
        result = -EDGE_LINUX_EIO;
        goto fail;
    }
    command.bo_handle = resource->bo_handle;
    command.res_handle = resource->resource_id;
    edge_virtgpu_unlock();
    if (edge_virtgpu_copy_to(
            request, request->argument, &command, sizeof(command)) < 0) {
        edge_virtgpu_lock();
        resource = edge_virtgpu_resource(identity, command.bo_handle);
        if (resource) edge_virtgpu_resource_release(resource);
        edge_virtgpu_unlock();
        return -EDGE_LINUX_EFAULT;
    }
    return 0;

fail:
    edge_virtgpu_unlock();
    edge_virtgpu_storage_release(storage, page_count);
    return result;
}

static int64_t edge_virtgpu_ioctl_resource_info(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_resource_info_t command;
    edge_virtgpu_resource_t *resource;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource(identity, command.bo_handle);
    if (!resource) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    command.res_handle = resource->resource_id;
    command.size = resource->size;
    command.blob_mem = resource->blob_mem;
    edge_virtgpu_unlock();
    return edge_virtgpu_copy_to(
               request, request->argument, &command, sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_ioctl_map(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_map_t command;
    edge_virtgpu_resource_t *resource;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource(identity, command.handle);
    if (!resource) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    command.offset = resource->map_offset;
    edge_virtgpu_unlock();
    return edge_virtgpu_copy_to(
               request, request->argument, &command, sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int edge_virtgpu_transfer_validate(
    const edge_virtgpu_resource_t *resource,
    const edge_virtgpu_transfer_uapi_t *command) {
    if (!resource || !command || !command->box.width ||
        !command->box.height || !command->box.depth ||
        command->offset >= resource->size)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int64_t edge_virtgpu_ioctl_transfer(
    uint64_t identity, const kernel_ioctl_request_t *request,
    int to_host) {
    edge_virtgpu_transfer_uapi_t command;
    edge_virtgpu_transfer_t transfer;
    edge_virtgpu_resource_t *resource;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource(identity, command.bo_handle);
    result = edge_virtgpu_transfer_validate(resource, &command);
    if (result < 0) {
        edge_virtgpu_unlock();
        return result;
    }
    memset(&transfer, 0, sizeof(transfer));
    transfer.x = command.box.x;
    transfer.y = command.box.y;
    transfer.z = command.box.z;
    transfer.width = command.box.width;
    transfer.height = command.box.height;
    transfer.depth = command.box.depth;
    transfer.level = command.level;
    transfer.offset = command.offset;
    transfer.stride = command.stride;
    transfer.layer_stride = command.layer_stride;
    if (to_host)
        result = g_edge_virtgpu_backend.operations.transfer_to_host(
            g_edge_virtgpu_backend.context, resource->context_id,
            resource->resource_id, &transfer);
    else
        result = g_edge_virtgpu_backend.operations.transfer_from_host(
            g_edge_virtgpu_backend.context, resource->context_id,
            resource->resource_id, &transfer);
    edge_virtgpu_unlock();
    return result < 0 ? -EDGE_LINUX_EIO : 0;
}

static int64_t edge_virtgpu_ioctl_execbuffer(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_execbuffer_t command;
    edge_virtgpu_client_t *client;
    uint32_t handles[EDGE_VIRTGPU_EXEC_HANDLE_COUNT];
    uint8_t *commands;
    uint32_t pages;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags & ~EDGE_VIRTGPU_EXECBUF_FLAGS)
        return -EDGE_LINUX_EINVAL;
    if (command.flags &
        (EDGE_VIRTGPU_EXECBUF_FENCE_FD_IN |
         EDGE_VIRTGPU_EXECBUF_FENCE_FD_OUT))
        return -EDGE_LINUX_EOPNOTSUPP;
    if ((command.flags & EDGE_VIRTGPU_EXECBUF_RING_IDX) &&
        command.ring_idx != 0u)
        return -EDGE_LINUX_EINVAL;
    if (command.syncobj_stride || command.num_in_syncobjs ||
        command.num_out_syncobjs || command.in_syncobjs ||
        command.out_syncobjs || !command.command || !command.size ||
        command.size > EDGE_VIRTGPU_MAX_COMMAND_SIZE ||
        command.size > g_edge_virtgpu_backend.info.maximum_command_size ||
        command.num_bo_handles > EDGE_VIRTGPU_EXEC_HANDLE_COUNT ||
        (command.num_bo_handles && !command.bo_handles))
        return -EDGE_LINUX_EINVAL;
    if (command.num_bo_handles &&
        edge_virtgpu_copy_from(
            request, handles, command.bo_handles,
            (uint64_t)command.num_bo_handles * sizeof(handles[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    pages = (command.size + EDGE_VIRTGPU_PAGE_SIZE - 1u) /
        EDGE_VIRTGPU_PAGE_SIZE;
    commands = arch_vm_alloc_pages(pages);
    if (!commands) return -EDGE_LINUX_ENOMEM;
    if (edge_virtgpu_copy_from(
            request, commands, command.command, command.size) < 0) {
        edge_virtgpu_storage_release(commands, pages);
        return -EDGE_LINUX_EFAULT;
    }

    edge_virtgpu_lock();
    client = edge_virtgpu_client(identity, 1);
    result = client ? edge_virtgpu_context_ensure(client) :
        -EDGE_LINUX_ENOSPC;
    for (uint32_t index = 0;
         result == 0 && index < command.num_bo_handles; ++index)
        if (!edge_virtgpu_resource(identity, handles[index]))
            result = -EDGE_LINUX_ENOENT;
    if (result == 0 &&
        g_edge_virtgpu_backend.operations.submit_3d(
            g_edge_virtgpu_backend.context, client->context_id,
            commands, command.size) < 0)
        result = -EDGE_LINUX_EIO;
    edge_virtgpu_unlock();
    edge_virtgpu_storage_release(commands, pages);
    return result;
}

static int64_t edge_virtgpu_ioctl_wait(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_wait_t command;
    edge_virtgpu_resource_t *resource;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags & ~EDGE_VIRTGPU_WAIT_NOWAIT)
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource(identity, command.handle);
    edge_virtgpu_unlock();
    return resource ? 0 : -EDGE_LINUX_ENOENT;
}

static int64_t edge_virtgpu_ioctl_get_caps(
    const kernel_ioctl_request_t *request) {
    edge_virtgpu_get_caps_t command;
    uint8_t *data;
    uint32_t pages;
    uint32_t actual = 0;
    uint32_t maximum;
    uint32_t transfer_size;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    maximum = g_edge_virtgpu_backend.info.maximum_capset_size;
    if (!command.address || !command.size || !maximum ||
        command.size > EDGE_VIRTGPU_MAX_CAPSET_SIZE ||
        command.cap_set_id >= 64u ||
        !(g_edge_virtgpu_backend.info.supported_capsets &
          (1ull << command.cap_set_id)))
        return -EDGE_LINUX_EINVAL;
    transfer_size = command.size < maximum ? command.size : maximum;
    pages = (command.size + EDGE_VIRTGPU_PAGE_SIZE - 1u) /
        EDGE_VIRTGPU_PAGE_SIZE;
    data = arch_vm_alloc_pages(pages);
    if (!data) return -EDGE_LINUX_ENOMEM;
    edge_virtgpu_lock();
    result = g_edge_virtgpu_backend.operations.get_capset(
        g_edge_virtgpu_backend.context, command.cap_set_id,
        command.cap_set_version, data, transfer_size, &actual);
    edge_virtgpu_unlock();
    if (result < 0 || actual > transfer_size)
        result = -EDGE_LINUX_EIO;
    else if (edge_virtgpu_copy_to(
                 request, command.address, data, actual) < 0)
        result = -EDGE_LINUX_EFAULT;
    else
        result = 0;
    edge_virtgpu_storage_release(data, pages);
    return result;
}

static int edge_virtgpu_copy_debug_name(
    const kernel_ioctl_request_t *request, uint64_t source,
    char destination[64]) {
    uint32_t index;

    if (!source) return -1;
    for (index = 0; index + 1u < 64u; ++index) {
        char character;
        if (edge_virtgpu_copy_from(
                request, &character, source + index, 1u) < 0)
            return -1;
        destination[index] = character;
        if (!character) return 0;
    }
    destination[index] = 0;
    return 0;
}

static int64_t edge_virtgpu_ioctl_context_init(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_context_init_t command;
    edge_virtgpu_context_param_t
        params[EDGE_VIRTGPU_CONTEXT_PARAM_COUNT];
    edge_virtgpu_client_t *client;
    uint32_t capset = 0;
    uint64_t debug_name = 0;
    int result = 0;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!(g_edge_virtgpu_backend.info.flags &
          EDGE_VIRTGPU_BACKEND_CONTEXT_INIT))
        return -EDGE_LINUX_EOPNOTSUPP;
    if (!command.num_params ||
        command.num_params > EDGE_VIRTGPU_CONTEXT_PARAM_COUNT ||
        !command.params || command.pad)
        return -EDGE_LINUX_EINVAL;
    if (edge_virtgpu_copy_from(
            request, params, command.params,
            (uint64_t)command.num_params * sizeof(params[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    for (uint32_t index = 0; index < command.num_params; ++index) {
        switch (params[index].param) {
            case EDGE_VIRTGPU_CONTEXT_PARAM_CAPSET_ID:
                if (params[index].value >= 64u)
                    return -EDGE_LINUX_EINVAL;
                capset = (uint32_t)params[index].value;
                break;
            case EDGE_VIRTGPU_CONTEXT_PARAM_NUM_RINGS:
                if (params[index].value != 1u)
                    return -EDGE_LINUX_EINVAL;
                break;
            case EDGE_VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK:
                if (params[index].value)
                    return -EDGE_LINUX_EOPNOTSUPP;
                break;
            case EDGE_VIRTGPU_CONTEXT_PARAM_DEBUG_NAME:
                debug_name = params[index].value;
                break;
            default:
                return -EDGE_LINUX_EINVAL;
        }
    }
    if (capset &&
        !(g_edge_virtgpu_backend.info.supported_capsets & (1ull << capset)))
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    client = edge_virtgpu_client(identity, 1);
    if (!client)
        result = -EDGE_LINUX_ENOSPC;
    else if (client->context_created)
        result = -EDGE_LINUX_EBUSY;
    else {
        if (capset) client->capset_id = capset;
        if (debug_name &&
            edge_virtgpu_copy_debug_name(
                request, debug_name, client->debug_name) < 0)
            result = -EDGE_LINUX_EFAULT;
        if (result == 0) result = edge_virtgpu_context_ensure(client);
    }
    edge_virtgpu_unlock();
    return result;
}

static int64_t edge_virtgpu_ioctl_gem_close(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_gem_close_t command;
    edge_virtgpu_resource_t *resource;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad) return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource_handle(identity, command.handle);
    if (!resource) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    resource->handle_open = 0u;
    edge_virtgpu_resource_maybe_release(resource);
    edge_virtgpu_unlock();
    return 0;
}

static int64_t edge_virtgpu_ioctl_prime_handle_to_fd(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_prime_handle_t command;
    edge_virtgpu_resource_t *resource;
    int32_t object_id;
    int descriptor;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags & ~EDGE_VIRTGPU_PRIME_FLAGS)
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource(identity, command.handle);
    if (!resource) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    if (resource->prime_refs == UINT32_MAX) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_EOVERFLOW;
    }
    object_id = edge_virtgpu_prime_object_id(resource);
    resource->prime_refs++;
    edge_virtgpu_unlock();

    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_PRIME, object_id,
        command.flags & EDGE_VIRTGPU_PRIME_RDWR,
        command.flags & EDGE_VIRTGPU_PRIME_CLOEXEC);
    if (descriptor < 0) {
        edge_virtgpu_prime_release(object_id);
        return descriptor;
    }
    command.fd = descriptor;
    if (edge_virtgpu_copy_to(
            request, request->argument, &command, sizeof(command)) < 0) {
        (void)kernel_fd_close(descriptor);
        return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

static int64_t edge_virtgpu_ioctl_prime_fd_to_handle(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_prime_handle_t command;
    edge_virtgpu_client_t *client;
    edge_virtgpu_resource_t *handle_record = 0;
    edge_virtgpu_resource_t *resource;
    int32_t object_id;
    int installed = 0;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    object_id = kernel_anonymous_fd_descriptor_object_id(
        command.fd, KERNEL_ANONYMOUS_FD_PRIME);
    if (object_id < 0) return object_id;

    edge_virtgpu_lock();
    resource = edge_virtgpu_prime_resource(object_id);
    if (!resource) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_EBADF;
    }
    client = edge_virtgpu_client(identity, 1);
    if (!client) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_ENOSPC;
    }
    if (edge_virtgpu_context_ensure(client) < 0) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_EIO;
    }
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index) {
        edge_virtgpu_resource_t *candidate =
            &g_edge_virtgpu_resources[index];
        if (!candidate->used || candidate->owner != identity)
            continue;
        if (candidate == resource ||
            candidate->backing_object_id == object_id) {
            handle_record = candidate;
            break;
        }
    }
    if (!handle_record) {
        if (resource->alias_refs == UINT32_MAX) {
            edge_virtgpu_unlock();
            return -EDGE_LINUX_EOVERFLOW;
        }
        for (uint32_t index = 0;
             index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index)
            if (!g_edge_virtgpu_resources[index].used) {
                handle_record = &g_edge_virtgpu_resources[index];
                break;
            }
        if (!handle_record) {
            edge_virtgpu_unlock();
            return -EDGE_LINUX_ENOSPC;
        }
        memset(handle_record, 0, sizeof(*handle_record));
        handle_record->used = 1u;
        handle_record->owner = identity;
        handle_record->bo_handle = g_edge_virtgpu_next_handle++;
        if (!handle_record->bo_handle)
            handle_record->bo_handle = g_edge_virtgpu_next_handle++;
        handle_record->backing_object_id = object_id;
        handle_record->context_id = client->context_id;
        if (!g_edge_virtgpu_backend.operations.resource_attach ||
            g_edge_virtgpu_backend.operations.resource_attach(
                g_edge_virtgpu_backend.context, client->context_id,
                resource->resource_id) < 0) {
            memset(handle_record, 0, sizeof(*handle_record));
            edge_virtgpu_unlock();
            return -EDGE_LINUX_EIO;
        }
        resource->alias_refs++;
        installed = 1;
    } else if (!handle_record->handle_open) {
        installed = 1;
    }
    handle_record->handle_open = 1u;
    command.handle = handle_record->bo_handle;
    command.flags = 0u;
    edge_virtgpu_unlock();
    if (edge_virtgpu_copy_to(
            request, request->argument, &command, sizeof(command)) < 0) {
        if (installed) {
            edge_virtgpu_lock();
            handle_record = edge_virtgpu_resource_record(
                identity, command.handle);
            if (handle_record && handle_record->handle_open) {
                handle_record->handle_open = 0u;
                edge_virtgpu_resource_maybe_release(handle_record);
            }
            edge_virtgpu_unlock();
        }
        return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

int edge_virtgpu_backend_register(const edge_virtgpu_backend_t *backend) {
    int result = -1;

    if (!backend || !backend->owner || !backend->name ||
        !(backend->info.flags & EDGE_VIRTGPU_BACKEND_VIRGL) ||
        !backend->info.supported_capsets ||
        !backend->info.maximum_command_size ||
        !backend->info.maximum_capset_size ||
        !backend->operations.context_create ||
        !backend->operations.context_destroy ||
        !backend->operations.resource_create ||
        !backend->operations.resource_destroy ||
        !backend->operations.transfer_to_host ||
        !backend->operations.transfer_from_host ||
        !backend->operations.submit_3d ||
        !backend->operations.get_capset)
        return -1;
    edge_virtgpu_lock();
    if (!g_edge_virtgpu_backend.owner) {
        g_edge_virtgpu_backend = *backend;
        result = 0;
    } else if (g_edge_virtgpu_backend.owner == backend->owner) {
        g_edge_virtgpu_backend = *backend;
        result = 0;
    }
    edge_virtgpu_unlock();
    return result;
}

void edge_virtgpu_backend_unregister(void *owner) {
    int busy = 0;

    if (!owner) return;
    edge_virtgpu_lock();
    for (uint32_t index = 0; index < EDGE_VIRTGPU_CLIENT_COUNT; ++index)
        if (g_edge_virtgpu_clients[index].used) busy = 1;
    if (!busy && g_edge_virtgpu_backend.owner == owner)
        memset(&g_edge_virtgpu_backend, 0,
               sizeof(g_edge_virtgpu_backend));
    edge_virtgpu_unlock();
}

int edge_virtgpu_available(void) {
    int available;
    edge_virtgpu_lock();
    available = g_edge_virtgpu_backend.owner != 0;
    edge_virtgpu_unlock();
    return available;
}

int edge_virtgpu_framebuffer_available(void) {
    int available;

    edge_virtgpu_lock();
    available = g_edge_virtgpu_backend.owner &&
        g_edge_virtgpu_backend.operations.present_resource;
    edge_virtgpu_unlock();
    return available;
}

const char *edge_virtgpu_driver_name(void) {
    return edge_virtgpu_available() ? "virtio_gpu" : 0;
}

int64_t edge_virtgpu_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    if (!identity || !request) return -EDGE_LINUX_EBADF;
    if (!edge_virtgpu_available()) return -EDGE_LINUX_ENODEV;
    switch (request->command) {
        case EDGE_VIRTGPU_IOCTL_VERSION:
            return edge_virtgpu_ioctl_version(request);
        case EDGE_VIRTGPU_IOCTL_GEM_CLOSE:
            return edge_virtgpu_ioctl_gem_close(identity, request);
        case EDGE_VIRTGPU_IOCTL_GET_CAP:
            return edge_virtgpu_ioctl_get_cap(request);
        case EDGE_VIRTGPU_IOCTL_PRIME_HANDLE_TO_FD:
            return edge_virtgpu_ioctl_prime_handle_to_fd(
                identity, request);
        case EDGE_VIRTGPU_IOCTL_PRIME_FD_TO_HANDLE:
            return edge_virtgpu_ioctl_prime_fd_to_handle(
                identity, request);
        case EDGE_VIRTGPU_IOCTL_MAP:
            return edge_virtgpu_ioctl_map(identity, request);
        case EDGE_VIRTGPU_IOCTL_EXECBUFFER:
            return edge_virtgpu_ioctl_execbuffer(identity, request);
        case EDGE_VIRTGPU_IOCTL_GETPARAM:
            return edge_virtgpu_ioctl_getparam(request);
        case EDGE_VIRTGPU_IOCTL_RESOURCE_CREATE:
            return edge_virtgpu_ioctl_resource_create(identity, request);
        case EDGE_VIRTGPU_IOCTL_RESOURCE_INFO:
            return edge_virtgpu_ioctl_resource_info(identity, request);
        case EDGE_VIRTGPU_IOCTL_TRANSFER_FROM:
            return edge_virtgpu_ioctl_transfer(identity, request, 0);
        case EDGE_VIRTGPU_IOCTL_TRANSFER_TO:
            return edge_virtgpu_ioctl_transfer(identity, request, 1);
        case EDGE_VIRTGPU_IOCTL_WAIT:
            return edge_virtgpu_ioctl_wait(identity, request);
        case EDGE_VIRTGPU_IOCTL_GET_CAPS:
            return edge_virtgpu_ioctl_get_caps(request);
        case EDGE_VIRTGPU_IOCTL_CREATE_BLOB:
            return -EDGE_LINUX_EOPNOTSUPP;
        case EDGE_VIRTGPU_IOCTL_CONTEXT_INIT:
            return edge_virtgpu_ioctl_context_init(identity, request);
        default:
            return -EDGE_LINUX_ENOTTY;
    }
}

void edge_virtgpu_release_client(uint64_t identity) {
    edge_virtgpu_client_t *client;

    if (!identity) return;
    edge_virtgpu_lock();
    client = edge_virtgpu_client(identity, 0);
    if (client) client->file_released = 1u;
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index)
        if (g_edge_virtgpu_resources[index].used &&
            g_edge_virtgpu_resources[index].owner == identity) {
            g_edge_virtgpu_resources[index].handle_open = 0u;
            edge_virtgpu_resource_maybe_release(
                &g_edge_virtgpu_resources[index]);
        }
    edge_virtgpu_client_maybe_release(client);
    edge_virtgpu_unlock();
}

int edge_virtgpu_prime_retain(int32_t object_id) {
    edge_virtgpu_resource_t *resource;
    int result = -EDGE_LINUX_EBADF;

    edge_virtgpu_lock();
    resource = edge_virtgpu_prime_resource(object_id);
    if (resource && resource->prime_refs != UINT32_MAX) {
        resource->prime_refs++;
        result = 0;
    } else if (resource) {
        result = -EDGE_LINUX_EOVERFLOW;
    }
    edge_virtgpu_unlock();
    return result;
}

void edge_virtgpu_prime_release(int32_t object_id) {
    edge_virtgpu_resource_t *resource;

    edge_virtgpu_lock();
    resource = edge_virtgpu_prime_resource(object_id);
    if (resource && resource->prime_refs) {
        resource->prime_refs--;
        edge_virtgpu_resource_maybe_release(resource);
    }
    edge_virtgpu_unlock();
}

int edge_virtgpu_framebuffer_acquire(
    uint64_t identity, uint32_t handle,
    edge_virtgpu_framebuffer_info_t *info) {
    edge_virtgpu_resource_t *backing;
    edge_virtgpu_resource_t *resource;
    int result = -EDGE_LINUX_ENOENT;

    if (!identity || !handle || !info)
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource_handle(identity, handle);
    backing = edge_virtgpu_resource_backing(resource);
    if (resource && backing &&
        resource->framebuffer_refs != UINT16_MAX) {
        resource->framebuffer_refs++;
        info->width = backing->width;
        info->height = backing->height;
        info->stride = backing->stride;
        info->size = backing->size;
        result = 0;
    }
    edge_virtgpu_unlock();
    return result;
}

void edge_virtgpu_framebuffer_release(
    uint64_t identity, uint32_t handle) {
    edge_virtgpu_resource_t *resource;

    if (!identity || !handle) return;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource_record(identity, handle);
    if (resource && resource->framebuffer_refs) {
        resource->framebuffer_refs--;
        edge_virtgpu_resource_maybe_release(resource);
    }
    edge_virtgpu_unlock();
}

int edge_virtgpu_framebuffer_present(
    uint64_t identity, uint32_t handle,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    edge_virtgpu_resource_t *backing;
    edge_virtgpu_resource_t *resource;
    int result = -EDGE_LINUX_ENOENT;

    if (!identity || !handle || !width || !height)
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    resource = edge_virtgpu_resource_record(identity, handle);
    backing = edge_virtgpu_resource_backing(resource);
    if (resource && backing && resource->framebuffer_refs &&
        x < backing->width && y < backing->height &&
        width <= backing->width - x &&
        height <= backing->height - y &&
        g_edge_virtgpu_backend.operations.present_resource)
        result = g_edge_virtgpu_backend.operations.present_resource(
            g_edge_virtgpu_backend.context, backing->resource_id,
            backing->width, backing->height,
            x, y, width, height) < 0 ?
            -EDGE_LINUX_EIO : 0;
    edge_virtgpu_unlock();
    return result;
}

int edge_virtgpu_framebuffer_reset(void) {
    int result;

    edge_virtgpu_lock();
    result = g_edge_virtgpu_backend.operations.present_resource ?
        g_edge_virtgpu_backend.operations.present_resource(
            g_edge_virtgpu_backend.context, 0u, 0u, 0u,
            0u, 0u, 0u, 0u) : -1;
    edge_virtgpu_unlock();
    return result < 0 ? -EDGE_LINUX_ENODEV : 0;
}

int edge_virtgpu_mmap_prepare(
    uint64_t identity, uint64_t offset, uint64_t length,
    uint32_t *page_count) {
    int result = -EDGE_LINUX_EINVAL;

    if (!identity || !length || !page_count ||
        (offset & (EDGE_VIRTGPU_PAGE_SIZE - 1u)) ||
        (length & (EDGE_VIRTGPU_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index) {
        edge_virtgpu_resource_t *resource =
            &g_edge_virtgpu_resources[index];
        edge_virtgpu_resource_t *backing;
        if (!resource->used || !resource->handle_open ||
            resource->owner != identity)
            continue;
        backing = edge_virtgpu_resource_backing(resource);
        if (!backing || backing->map_offset != offset) continue;
        if (length >
            (uint64_t)backing->page_count * EDGE_VIRTGPU_PAGE_SIZE)
            break;
        *page_count =
            (uint32_t)(length / EDGE_VIRTGPU_PAGE_SIZE);
        result = 0;
        break;
    }
    edge_virtgpu_unlock();
    return result;
}

int edge_virtgpu_mmap_page(
    uint64_t identity, uint64_t offset, uint32_t page_index,
    void **kernel_address) {
    int result = -EDGE_LINUX_EINVAL;

    if (!identity || !kernel_address) return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index) {
        edge_virtgpu_resource_t *resource =
            &g_edge_virtgpu_resources[index];
        edge_virtgpu_resource_t *backing;
        if (!resource->used || !resource->handle_open ||
            resource->owner != identity)
            continue;
        backing = edge_virtgpu_resource_backing(resource);
        if (!backing || backing->map_offset != offset) continue;
        if (page_index >= backing->page_count) break;
        *kernel_address =
            backing->storage +
            (uint64_t)page_index * EDGE_VIRTGPU_PAGE_SIZE;
        result = 0;
        break;
    }
    edge_virtgpu_unlock();
    return result;
}
