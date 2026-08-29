/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared Linux virtgpu render runtime. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/anonymous_fd.h"
#include "kernel/drm_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/virtgpu_runtime.h"

#define DRM_IOCTL_VERSION                  0xc0406400u
#define DRM_IOCTL_GEM_CLOSE                0x40086409u
#define DRM_IOCTL_GET_CAP                  0xc010640cu
#define DRM_IOCTL_PRIME_HANDLE_TO_FD       0xc00c642du
#define DRM_IOCTL_PRIME_FD_TO_HANDLE       0xc00c642eu
#define DRM_IOCTL_VIRTGPU_MAP              0xc0106441u
#define DRM_IOCTL_VIRTGPU_EXECBUFFER       0xc0406442u
#define DRM_IOCTL_VIRTGPU_GETPARAM         0xc0106443u
#define DRM_IOCTL_VIRTGPU_RESOURCE_CREATE  0xc0386444u
#define DRM_IOCTL_VIRTGPU_RESOURCE_INFO    0xc0106445u
#define DRM_IOCTL_VIRTGPU_TRANSFER_FROM    0xc02c6446u
#define DRM_IOCTL_VIRTGPU_TRANSFER_TO      0xc02c6447u
#define DRM_IOCTL_VIRTGPU_WAIT             0xc0086448u
#define DRM_IOCTL_VIRTGPU_GET_CAPS         0xc0186449u
#define DRM_IOCTL_VIRTGPU_CONTEXT_INIT     0xc010644bu
#define DRM_IOCTL_SYNCOBJ_CREATE           0xc00864bfu
#define DRM_IOCTL_SYNCOBJ_DESTROY          0xc00864c0u
#define DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD     0xc01864c1u
#define DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE     0xc01864c2u
#define DRM_IOCTL_SYNCOBJ_WAIT             0xc02864c3u
#define DRM_IOCTL_SYNCOBJ_RESET            0xc01064c4u
#define DRM_IOCTL_SYNCOBJ_SIGNAL           0xc01064c5u
#define DRM_IOCTL_SYNCOBJ_QUERY            0xc01864cbu
#define DRM_IOCTL_SYNCOBJ_TRANSFER         0xc02064ccu
#define DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL  0xc01864cdu
#define DRM_IOCTL_SYNCOBJ_EVENTFD          0xc01864cfu
#define SYNC_IOC_FILE_INFO                 0xc0383e04u
#define SYNC_IOC_SET_DEADLINE              0x40103e05u
#define DRM_RDWR                           0x00000002u
#define DRM_CLOEXEC                        0x00080000u

typedef struct {
    int32_t major;
    int32_t minor;
    int32_t patch;
    uint32_t pad;
    uint64_t name_len;
    uint64_t name;
    uint64_t date_len;
    uint64_t date;
    uint64_t desc_len;
    uint64_t desc;
} test_version_t;

typedef struct {
    uint64_t param;
    uint64_t value;
} test_getparam_t;

typedef struct {
    uint64_t capability;
    uint64_t value;
} test_get_cap_t;

typedef struct {
    uint64_t param;
    uint64_t value;
} test_context_param_t;

typedef struct {
    uint32_t num_params;
    uint32_t pad;
    uint64_t params;
} test_context_init_t;

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
} test_resource_create_t;

typedef struct {
    uint32_t bo_handle;
    uint32_t res_handle;
    uint32_t size;
    uint32_t blob_mem;
} test_resource_info_t;

typedef struct {
    uint64_t offset;
    uint32_t handle;
    uint32_t pad;
} test_map_t;

typedef struct {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
} test_box_t;

typedef struct {
    uint32_t bo_handle;
    test_box_t box;
    uint32_t level;
    uint32_t offset;
    uint32_t stride;
    uint32_t layer_stride;
} test_transfer_t;

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
} test_execbuffer_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
} test_wait_t;

typedef struct {
    uint32_t capset;
    uint32_t version;
    uint64_t address;
    uint32_t size;
    uint32_t pad;
} test_get_caps_t;

typedef struct {
    uint32_t handle;
    uint32_t pad;
} test_gem_close_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    int32_t fd;
} test_prime_handle_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
} test_syncobj_create_t;

typedef struct {
    uint32_t handle;
    uint32_t pad;
} test_syncobj_destroy_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    int32_t fd;
    uint32_t pad;
    uint64_t point;
} test_syncobj_handle_t;

typedef struct {
    uint64_t handles;
    int64_t timeout_ns;
    uint32_t count_handles;
    uint32_t flags;
    uint32_t first_signaled;
    uint32_t pad;
    uint64_t deadline_ns;
} test_syncobj_wait_t;

typedef struct {
    uint64_t handles;
    uint64_t points;
    uint32_t count_handles;
    uint32_t flags;
} test_syncobj_timeline_array_t;

typedef struct {
    uint64_t handles;
    uint32_t count_handles;
    uint32_t pad;
} test_syncobj_array_t;

typedef struct {
    uint32_t source_handle;
    uint32_t destination_handle;
    uint64_t source_point;
    uint64_t destination_point;
    uint32_t flags;
    uint32_t pad;
} test_syncobj_transfer_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    uint64_t point;
    int32_t fd;
    uint32_t pad;
} test_syncobj_eventfd_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    uint64_t point;
} test_execbuffer_syncobj_t;

typedef struct {
    char obj_name[32];
    char driver_name[32];
    int32_t status;
    uint32_t flags;
    uint64_t timestamp_ns;
} test_sync_fence_info_t;

typedef struct {
    char name[32];
    int32_t status;
    uint32_t flags;
    uint32_t num_fences;
    uint32_t pad;
    uint64_t sync_fence_info;
} test_sync_file_info_t;

typedef struct {
    uint64_t deadline_ns;
    uint64_t pad;
} test_sync_set_deadline_t;

typedef struct {
    uint32_t contexts_created;
    uint32_t contexts_destroyed;
    uint32_t resources_created;
    uint32_t resources_destroyed;
    uint32_t resources_attached;
    uint32_t resources_detached;
    uint32_t transfers_to;
    uint32_t transfers_from;
    uint32_t submissions;
    uint32_t presents;
    uint32_t context_id;
    uint32_t capset_id;
    uint32_t resource_id;
    uint32_t resource_context_id;
    uint32_t attached_context_id;
    uint64_t deferred_completion_id;
    uint8_t defer_submission;
    void *storage;
    uint64_t storage_size;
} test_backend_state_t;

static uint32_t g_allocation_max_pages;

static int test_context_create(void *context, uint32_t context_id,
                               uint32_t capset_id, const char *name) {
    test_backend_state_t *state = context;

    assert(edge_virtgpu_sync_file_ready(-1) < 0);
    assert(name &&
           (strcmp(name, "renderer-unit") == 0 ||
            strcmp(name, "edgeos-virtgpu") == 0));
    state->contexts_created++;
    state->context_id = context_id;
    state->capset_id = capset_id;
    return 0;
}

uint64_t boottime_monotonic_us(void) {
    static uint64_t now_us = 1u;

    return now_us++;
}

static int test_context_destroy(void *context, uint32_t context_id) {
    test_backend_state_t *state = context;
    assert(context_id);
    /* Backend teardown must run after the runtime state lock is released. */
    assert(edge_virtgpu_sync_file_ready(-1) < 0);
    state->contexts_destroyed++;
    return 0;
}

static int test_resource_create(
    void *context, uint32_t context_id, uint32_t resource_id,
    const edge_virtgpu_resource_create_t *create,
    const edge_virtgpu_backing_t *backing, uint64_t size) {
    test_backend_state_t *state = context;

    assert(edge_virtgpu_sync_file_ready(-1) < 0);
    assert(context_id == state->context_id);
    assert(create && backing && backing->segments);
    assert(backing->segments[0].address);
    if (!state->resources_created) {
        assert(create->width == 0u && create->height == 0u);
        assert(create->depth == 0u && create->array_size == 0u);
        assert(size == 5u * 4096u);
        assert(backing->page_count == 5u);
        assert(backing->segment_count == 3u);
        assert(backing->segments[0].page_count == 2u);
        assert(backing->segments[1].page_count == 1u);
        assert(backing->segments[2].page_count == 2u);
    } else {
        assert(create->width == 64u && create->height == 32u);
        assert(size == 8192u);
        assert(backing->page_count == 2u);
        assert(backing->segment_count == 1u);
        assert(backing->segments[0].page_count == 2u);
    }
    state->resources_created++;
    state->resource_id = resource_id;
    state->resource_context_id = context_id;
    state->storage = backing->segments[0].address;
    state->storage_size = size;
    return 0;
}

static int test_resource_destroy(
    void *context, uint32_t context_id, uint32_t resource_id) {
    test_backend_state_t *state = context;
    assert(context_id == state->resource_context_id);
    assert(resource_id == state->resource_id);
    assert(edge_virtgpu_sync_file_ready(-1) < 0);
    state->resources_destroyed++;
    return 0;
}

static int test_resource_attach(
    void *context, uint32_t context_id, uint32_t resource_id) {
    test_backend_state_t *state = context;

    assert(edge_virtgpu_sync_file_ready(-1) < 0);
    assert(context_id != state->resource_context_id);
    assert(resource_id == state->resource_id);
    state->resources_attached++;
    state->attached_context_id = context_id;
    return 0;
}

static int test_resource_detach(
    void *context, uint32_t context_id, uint32_t resource_id) {
    test_backend_state_t *state = context;
    assert(context_id == state->attached_context_id);
    assert(resource_id == state->resource_id);
    assert(edge_virtgpu_sync_file_ready(-1) < 0);
    state->resources_detached++;
    return 0;
}

static int test_transfer_to(
    void *context, uint32_t context_id, uint32_t resource_id,
    const edge_virtgpu_transfer_t *transfer) {
    test_backend_state_t *state = context;
    assert(context_id == state->context_id);
    assert(resource_id == state->resource_id);
    assert(transfer && transfer->width == 64u);
    state->transfers_to++;
    return 0;
}

static int test_transfer_from(
    void *context, uint32_t context_id, uint32_t resource_id,
    const edge_virtgpu_transfer_t *transfer) {
    test_backend_state_t *state = context;
    assert(context_id == state->context_id);
    assert(resource_id == state->resource_id);
    assert(transfer && transfer->height == 32u);
    state->transfers_from++;
    return 0;
}

static int test_present_resource(
    void *context, uint32_t resource_id,
    uint32_t resource_width, uint32_t resource_height,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    test_backend_state_t *state = context;

    assert(resource_id == state->resource_id);
    assert(resource_width == 64u && resource_height == 32u);
    assert(x == 0u && y == 0u);
    assert(width == 64u && height == 32u);
    state->presents++;
    return 0;
}

static int test_submit(
    void *context, uint32_t context_id,
    const void *commands, uint32_t size, uint64_t completion_id) {
    static const uint8_t expected[] = { 1u, 2u, 3u, 4u };
    test_backend_state_t *state = context;
    assert(context_id == state->resource_context_id ||
           context_id == state->attached_context_id);
    assert(size == sizeof(expected));
    assert(completion_id != 0u);
    assert(memcmp(commands, expected, sizeof(expected)) == 0);
    state->submissions++;
    if (state->defer_submission)
        state->deferred_completion_id = completion_id;
    else
        edge_virtgpu_backend_submission_complete(completion_id, 0);
    return 0;
}

static int test_get_capset(
    void *context, uint32_t capset_id, uint32_t version,
    void *data, uint32_t size, uint32_t *actual_size) {
    (void)context;
    assert(edge_virtgpu_sync_file_ready(-1) < 0);
    assert(capset_id == 2u);
    assert(version == 1u);
    assert(size == 16u);
    memset(data, 0x5au, size);
    *actual_size = size;
    return 0;
}

static int64_t test_ioctl(
    uint64_t client, uint32_t command, void *argument);

static uint8_t g_submit_foreign_on_allocation;
static uint64_t g_allocation_submit_client;
static test_execbuffer_t *g_allocation_submit_execute;
static test_backend_state_t *g_allocation_submit_state;
static uint64_t g_wait_completion_id;
static uint8_t g_complete_deferred_on_wait;

void *arch_vm_alloc_pages(uint64_t page_count) {
    void *memory = 0;

    if (g_submit_foreign_on_allocation) {
        g_submit_foreign_on_allocation = 0u;
        assert(g_allocation_submit_execute);
        assert(g_allocation_submit_state);
        assert(test_ioctl(
                   g_allocation_submit_client,
                   DRM_IOCTL_VIRTGPU_EXECBUFFER,
                   g_allocation_submit_execute) == 0);
        g_wait_completion_id =
            g_allocation_submit_state->deferred_completion_id;
        assert(g_wait_completion_id != 0u);
        g_allocation_submit_state->defer_submission = 0u;
    }
    if (g_allocation_max_pages && page_count > g_allocation_max_pages)
        return 0;
    if (posix_memalign(&memory, 4096u, (size_t)page_count * 4096u) != 0)
        return 0;
    memset(memory, 0, (size_t)page_count * 4096u);
    return memory;
}

void arch_vm_free_page(void *page) {
    (void)page;
}

static uint32_t g_eventfd_writes;

int kernel_eventfd_retain(int event_id) {
    return event_id == 1 ? 0 : -EDGE_LINUX_EBADF;
}

void kernel_eventfd_release(int event_id) {
    assert(event_id == 1);
}

int64_t kernel_eventfd_write_value(int event_id, int nonblocking,
                                   uint64_t value) {
    assert(event_id == 1);
    assert(nonblocking == 1);
    assert(value == 1u);
    g_eventfd_writes++;
    return 8;
}

static int32_t g_prime_descriptor = -1;
static int32_t g_prime_object = -1;
static int32_t g_sync_descriptor = -1;
static int32_t g_sync_object = -1;
static uint32_t g_sync_notifications;

void kernel_drm_sync_state_changed(int32_t object_id) {
    assert(object_id > 0);
    g_sync_notifications++;
}

int kernel_runtime_yield(void) {
    return 1;
}

int kernel_runtime_wait_sequence(volatile uint64_t *sequence,
                                 uint64_t observed,
                                 uint64_t deadline_microseconds) {
    (void)deadline_microseconds;
    if (g_complete_deferred_on_wait && g_wait_completion_id) {
        uint64_t completion_id = g_wait_completion_id;

        g_complete_deferred_on_wait = 0u;
        g_wait_completion_id = 0u;
        edge_virtgpu_backend_submission_complete(completion_id, 0);
    }
    return sequence &&
        __atomic_load_n(sequence, __ATOMIC_ACQUIRE) != observed;
}

void kernel_runtime_notify_sequence(volatile uint64_t *sequence) {
    (void)sequence;
}

int kernel_anonymous_fd_install_descriptor(
    kernel_anonymous_fd_kind_t kind, int32_t object_id,
    uint32_t status_flags, uint32_t descriptor_flags) {
    assert(object_id > 0);
    assert(status_flags == DRM_RDWR);
    assert(descriptor_flags == DRM_CLOEXEC);
    if (kind == KERNEL_ANONYMOUS_FD_PRIME) {
        assert(g_prime_descriptor < 0);
        g_prime_descriptor = 71;
        g_prime_object = object_id;
        return g_prime_descriptor;
    }
    assert(kind == KERNEL_ANONYMOUS_FD_DRM_SYNC);
    assert(g_sync_descriptor < 0);
    g_sync_descriptor = 72;
    g_sync_object = object_id;
    return g_sync_descriptor;
}

int kernel_anonymous_fd_descriptor_object_id(
    int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    if (kind == KERNEL_ANONYMOUS_FD_PRIME &&
        descriptor == g_prime_descriptor)
        return g_prime_object;
    if (kind == KERNEL_ANONYMOUS_FD_DRM_SYNC &&
        descriptor == g_sync_descriptor)
        return g_sync_object;
    if (kind == KERNEL_ANONYMOUS_FD_EVENT && descriptor == 73)
        return 1;
    return -EDGE_LINUX_EBADF;
}

int kernel_fd_close(int32_t descriptor) {
    if (descriptor == g_prime_descriptor) {
        edge_virtgpu_prime_release(g_prime_object);
        g_prime_descriptor = -1;
        g_prime_object = -1;
        return 0;
    }
    if (descriptor == g_sync_descriptor) {
        edge_virtgpu_sync_file_release(g_sync_object);
        g_sync_descriptor = -1;
        g_sync_object = -1;
        return 0;
    }
    return -EDGE_LINUX_EBADF;
}

static int test_copy_from(void *context, void *destination,
                          uint64_t source, uint64_t length) {
    (void)context;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}

static int test_copy_to(void *context, uint64_t destination,
                        const void *source, uint64_t length) {
    (void)context;
    memcpy((void *)(uintptr_t)destination, source, (size_t)length);
    return 0;
}

static int64_t test_ioctl(
    uint64_t client, uint32_t command, void *argument) {
    kernel_ioctl_request_t request = {
        .descriptor = 9,
        .command = command,
        .argument = (uint64_t)(uintptr_t)argument,
        .copy_context = 0,
        .copy_from_user = test_copy_from,
        .copy_to_user = test_copy_to,
    };
    return edge_virtgpu_ioctl(client, &request);
}

static int64_t test_syncobj_ioctl(
    uint64_t client, uint32_t command, void *argument) {
    kernel_ioctl_request_t request = {
        .descriptor = 9,
        .command = command,
        .argument = (uint64_t)(uintptr_t)argument,
        .copy_context = 0,
        .copy_from_user = test_copy_from,
        .copy_to_user = test_copy_to,
    };
    return edge_virtgpu_syncobj_ioctl(client, &request);
}

static int64_t test_sync_file_ioctl(
    int32_t object_id, uint32_t command, void *argument) {
    kernel_ioctl_request_t request = {
        .descriptor = g_sync_descriptor,
        .command = command,
        .argument = (uint64_t)(uintptr_t)argument,
        .copy_context = 0,
        .copy_from_user = test_copy_from,
        .copy_to_user = test_copy_to,
    };
    return edge_virtgpu_sync_file_ioctl(object_id, &request);
}

int main(void) {
    static const uint64_t client = 0x55667788u;
    static const uint64_t importing_client = 0x11223344u;
    test_backend_state_t state = {0};
    int owner;
    edge_virtgpu_backend_t backend = {
        .name = "virtio_gpu",
        .owner = &owner,
        .context = &state,
        .info = {
            .flags = EDGE_VIRTGPU_BACKEND_VIRGL |
                     EDGE_VIRTGPU_BACKEND_CAPSET_QUERY_FIX |
                     EDGE_VIRTGPU_BACKEND_CONTEXT_INIT,
            .supported_capsets = (1ull << 1) | (1ull << 2),
            .maximum_command_size = 4096u,
            .maximum_capset_size = 4096u,
        },
        .operations = {
            .context_create = test_context_create,
            .context_destroy = test_context_destroy,
            .resource_create = test_resource_create,
            .resource_destroy = test_resource_destroy,
            .resource_attach = test_resource_attach,
            .resource_detach = test_resource_detach,
            .transfer_to_host = test_transfer_to,
            .transfer_from_host = test_transfer_from,
            .submit_3d = test_submit,
            .get_capset = test_get_capset,
            .present_resource = test_present_resource,
        },
    };
    char name[16] = {0};
    test_version_t version = {
        .name_len = sizeof(name),
        .name = (uint64_t)(uintptr_t)name,
    };
    uint64_t parameter_value = 0;
    test_getparam_t parameter = {
        .param = 1u,
        .value = (uint64_t)(uintptr_t)&parameter_value,
    };
    test_get_cap_t prime_capability = {
        .capability = EDGE_DRM_CAP_PRIME,
    };
    test_get_cap_t unsupported_capability = {
        .capability = 0xffffu,
    };
    const struct {
        uint64_t capability;
        uint64_t value;
    } linux_capabilities[] = {
        { EDGE_DRM_CAP_DUMB_BUFFER, 1u },
        { EDGE_DRM_CAP_VBLANK_HIGH_CRTC, 1u },
        { EDGE_DRM_CAP_DUMB_PREFERRED_DEPTH, 0u },
        { EDGE_DRM_CAP_DUMB_PREFER_SHADOW, 0u },
        { EDGE_DRM_CAP_PRIME,
          EDGE_DRM_PRIME_CAP_IMPORT | EDGE_DRM_PRIME_CAP_EXPORT },
        { EDGE_DRM_CAP_TIMESTAMP_MONOTONIC, 1u },
        { EDGE_DRM_CAP_ASYNC_PAGE_FLIP, 0u },
        { EDGE_DRM_CAP_CURSOR_WIDTH, 64u },
        { EDGE_DRM_CAP_CURSOR_HEIGHT, 64u },
        { EDGE_DRM_CAP_ADDFB2_MODIFIERS, 0u },
        { EDGE_DRM_CAP_PAGE_FLIP_TARGET, 0u },
        { EDGE_DRM_CAP_CRTC_IN_VBLANK_EVENT, 1u },
        { EDGE_DRM_CAP_SYNCOBJ, 1u },
        { EDGE_DRM_CAP_SYNCOBJ_TIMELINE, 1u },
    };
    char debug_name[] = "renderer-unit";
    test_context_param_t context_params[] = {
        { .param = 1u, .value = 2u },
        { .param = 2u, .value = 1u },
        { .param = 4u, .value = (uint64_t)(uintptr_t)debug_name },
    };
    test_context_init_t context = {
        .num_params = 3u,
        .params = (uint64_t)(uintptr_t)context_params,
    };
    test_resource_create_t create = {
        .target = 2u,
        .format = 1u,
        .bind = 1u,
        .width = 64u,
        .height = 32u,
        .depth = 1u,
        .array_size = 1u,
        .size = 8192u,
        .stride = 256u,
    };
    test_resource_create_t compatibility_create = {
        .bo_handle = 0xdeadbeefu,
        .res_handle = 0xcafebabeu,
        .size = 5u * 4096u,
    };
    test_resource_info_t info;
    edge_virtgpu_framebuffer_info_t framebuffer_info;
    test_map_t mapping;
    test_transfer_t transfer;
    uint8_t commands[] = { 1u, 2u, 3u, 4u };
    uint32_t handles[1];
    test_execbuffer_t execute;
    test_wait_t wait;
    uint8_t capabilities[16] = {0};
    test_get_caps_t get_caps = {
        .capset = 2u,
        .version = 1u,
        .address = (uint64_t)(uintptr_t)capabilities,
        .size = sizeof(capabilities),
    };
    test_gem_close_t close;
    test_prime_handle_t prime;
    test_prime_handle_t imported;
    test_prime_handle_t cross_imported;
    test_syncobj_create_t sync_a = {0};
    test_syncobj_create_t sync_b = {0};
    test_syncobj_create_t sync_import_target = {0};
    test_syncobj_wait_t sync_wait;
    test_syncobj_array_t sync_array;
    test_syncobj_timeline_array_t sync_timeline;
    test_syncobj_transfer_t sync_transfer;
    test_syncobj_eventfd_t sync_event;
    test_syncobj_handle_t sync_file;
    test_syncobj_handle_t sync_import;
    test_syncobj_destroy_t sync_destroy;
    test_execbuffer_syncobj_t output_syncobj;
    test_sync_file_info_t sync_info;
    test_sync_fence_info_t fence_info;
    test_sync_set_deadline_t sync_deadline;
    uint32_t sync_handles[1];
    uint64_t sync_points[1];
    uint32_t pages;
    void *first_page = 0;
    void *second_page = 0;

    assert(edge_virtgpu_backend_register(&backend) == 0);
    assert(edge_virtgpu_available());
    assert(strcmp(edge_virtgpu_driver_name(), "virtio_gpu") == 0);
    assert(test_ioctl(client, DRM_IOCTL_VERSION, &version) == 0);
    assert(version.major == 0);
    assert(version.minor == 1);
    assert(version.patch == 0);
    assert(strcmp(name, "virtio_gpu") == 0);
    assert(test_ioctl(client, DRM_IOCTL_GET_CAP, &prime_capability) == 0);
    assert(prime_capability.value ==
           (EDGE_DRM_PRIME_CAP_IMPORT | EDGE_DRM_PRIME_CAP_EXPORT));
    for (uint32_t index = 0;
         index < sizeof(linux_capabilities) / sizeof(linux_capabilities[0]);
         ++index) {
        test_get_cap_t capability = {
            .capability = linux_capabilities[index].capability,
        };

        assert(test_ioctl(client, DRM_IOCTL_GET_CAP, &capability) == 0);
        assert(capability.value == linux_capabilities[index].value);
    }
    assert(test_ioctl(client, DRM_IOCTL_GET_CAP,
                      &unsupported_capability) == -EDGE_LINUX_EINVAL);
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_GETPARAM, &parameter) == 0);
    assert(parameter_value == 1u);
    parameter.param = 8u;
    parameter_value = 0u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_GETPARAM, &parameter) == 0);
    assert(parameter_value == 1u);
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_GET_CAPS, &get_caps) == 0);
    for (uint32_t index = 0; index < sizeof(capabilities); ++index)
        assert(capabilities[index] == 0x5au);

    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &context) == 0);
    assert(state.contexts_created == 1u && state.capset_id == 2u);
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &context) ==
           -EDGE_LINUX_EEXIST);
    g_allocation_max_pages = 2u;
    assert(test_ioctl(
               client, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE,
               &compatibility_create) == 0);
    g_allocation_max_pages = 0u;
    assert(compatibility_create.bo_handle != 0xdeadbeefu);
    assert(compatibility_create.res_handle != 0xcafebabeu);
    close.handle = compatibility_create.bo_handle;
    close.pad = 0u;
    assert(test_ioctl(client, DRM_IOCTL_GEM_CLOSE, &close) == 0);
    assert(state.resources_destroyed == 1u);
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE, &create) == 0);
    assert(create.bo_handle && create.res_handle);
    memset(&info, 0, sizeof(info));
    info.bo_handle = create.bo_handle;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_RESOURCE_INFO, &info) == 0);
    assert(info.res_handle == create.res_handle && info.size == 8192u);
    assert(edge_virtgpu_framebuffer_acquire(
               client, create.bo_handle, &framebuffer_info) == 0);
    assert(framebuffer_info.width == 64u);
    assert(framebuffer_info.height == 32u);
    assert(framebuffer_info.stride == 256u);
    assert(framebuffer_info.size == 8192u);
    assert(edge_virtgpu_framebuffer_present(
               client, create.bo_handle,
               0u, 0u, 64u, 32u) == 0);

    memset(&mapping, 0, sizeof(mapping));
    mapping.handle = create.bo_handle;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_MAP, &mapping) == 0);
    assert(mapping.offset >= UINT64_C(0x100000000));
    assert(edge_virtgpu_mmap_prepare(
               client, mapping.offset, 8192u, &pages) == 0);
    assert(pages == 2u);
    assert(edge_virtgpu_mmap_page(
               client, mapping.offset, 0u, &first_page) == 0);
    assert(edge_virtgpu_mmap_page(
               client, mapping.offset, 1u, &second_page) == 0);
    assert(first_page == state.storage);
    assert(second_page == (uint8_t *)state.storage + 4096u);

    memset(&transfer, 0, sizeof(transfer));
    transfer.bo_handle = create.bo_handle;
    transfer.box.width = 64u;
    transfer.box.height = 32u;
    transfer.box.depth = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_TRANSFER_TO, &transfer) == 0);
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_TRANSFER_FROM, &transfer) == 0);

    handles[0] = create.bo_handle;
    memset(&execute, 0, sizeof(execute));
    execute.size = sizeof(commands);
    execute.command = (uint64_t)(uintptr_t)commands;
    execute.bo_handles = (uint64_t)(uintptr_t)handles;
    execute.num_bo_handles = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execute) == 0);
    wait.handle = create.bo_handle;
    wait.flags = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_WAIT, &wait) == 0);

    state.defer_submission = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execute) == 0);
    assert(state.deferred_completion_id != 0u);
    wait.flags = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_WAIT, &wait) ==
           -EDGE_LINUX_EBUSY);
    g_wait_completion_id = state.deferred_completion_id;
    g_complete_deferred_on_wait = 1u;
    assert(edge_virtgpu_framebuffer_present(
               client, create.bo_handle,
               0u, 0u, 64u, 32u) == 0);
    assert(g_wait_completion_id && g_complete_deferred_on_wait);
    assert(state.presents == 1u);
    wait.flags = 0u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_WAIT, &wait) == 0);
    assert(!g_wait_completion_id && !g_complete_deferred_on_wait);
    assert(state.presents == 2u);
    state.deferred_completion_id = 0u;
    state.defer_submission = 0u;

    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_CREATE, &sync_a) == 0);
    assert(sync_a.handle != 0u);
    sync_handles[0] = sync_a.handle;
    memset(&sync_wait, 0, sizeof(sync_wait));
    sync_wait.handles = (uint64_t)(uintptr_t)sync_handles;
    sync_wait.count_handles = 1u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_WAIT, &sync_wait) ==
           -EDGE_LINUX_ETIME);
    sync_points[0] = 9u;
    memset(&sync_timeline, 0, sizeof(sync_timeline));
    sync_timeline.handles = (uint64_t)(uintptr_t)sync_handles;
    sync_timeline.points = (uint64_t)(uintptr_t)sync_points;
    sync_timeline.count_handles = 1u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL,
               &sync_timeline) == 0);
    sync_points[0] = 0u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_QUERY, &sync_timeline) == 0);
    assert(sync_points[0] == 9u);
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_CREATE, &sync_b) == 0);
    memset(&sync_transfer, 0, sizeof(sync_transfer));
    sync_transfer.source_handle = sync_a.handle;
    sync_transfer.destination_handle = sync_b.handle;
    sync_transfer.source_point = 9u;
    sync_transfer.destination_point = 4u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_TRANSFER, &sync_transfer) == 0);

    sync_handles[0] = sync_b.handle;
    memset(&sync_array, 0, sizeof(sync_array));
    sync_array.handles = (uint64_t)(uintptr_t)sync_handles;
    sync_array.count_handles = 1u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_RESET, &sync_array) == 0);
    memset(&sync_event, 0, sizeof(sync_event));
    sync_event.handle = sync_b.handle;
    sync_event.fd = 73;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_EVENTFD, &sync_event) == 0);
    assert(g_eventfd_writes == 0u);
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_SIGNAL, &sync_array) == 0);
    assert(g_eventfd_writes == 1u);

    memset(&sync_file, 0, sizeof(sync_file));
    sync_file.handle = sync_b.handle;
    sync_file.flags = 1u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD,
               &sync_file) == 0);
    assert(sync_file.fd == 72);
    memset(&sync_import, 0, sizeof(sync_import));
    assert(test_syncobj_ioctl(
               importing_client, DRM_IOCTL_SYNCOBJ_CREATE,
               &sync_import_target) == 0);
    sync_import.handle = sync_import_target.handle;
    sync_import.flags = 1u;
    sync_import.fd = sync_file.fd;
    assert(test_syncobj_ioctl(
               importing_client, DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE,
               &sync_import) == 0);
    assert(sync_import.handle == sync_import_target.handle);
    assert(edge_virtgpu_sync_file_ready(g_sync_object) == 1);
    assert(kernel_fd_close(sync_file.fd) == 0);

    sync_handles[0] = sync_a.handle;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_RESET, &sync_array) == 0);
    output_syncobj.handle = sync_a.handle;
    output_syncobj.flags = 0u;
    output_syncobj.point = 0u;
    memset(&sync_event, 0, sizeof(sync_event));
    sync_event.handle = sync_a.handle;
    sync_event.fd = 73;
    sync_event.flags = 4u;
    g_eventfd_writes = 0u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_EVENTFD, &sync_event) == 0);
    execute.syncobj_stride = sizeof(output_syncobj);
    execute.num_out_syncobjs = 1u;
    execute.out_syncobjs = (uint64_t)(uintptr_t)&output_syncobj;
    state.defer_submission = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execute) == 0);
    assert(g_eventfd_writes == 1u);
    memset(&sync_wait, 0, sizeof(sync_wait));
    sync_wait.handles = (uint64_t)(uintptr_t)sync_handles;
    sync_wait.count_handles = 1u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_WAIT, &sync_wait) ==
           -EDGE_LINUX_ETIME);
    assert(state.deferred_completion_id != 0u);
    g_wait_completion_id = state.deferred_completion_id;
    g_complete_deferred_on_wait = 1u;
    state.defer_submission = 0u;
    execute.num_in_syncobjs = 1u;
    execute.in_syncobjs = (uint64_t)(uintptr_t)&output_syncobj;
    execute.num_out_syncobjs = 0u;
    execute.out_syncobjs = 0u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execute) == 0);
    assert(!g_wait_completion_id && !g_complete_deferred_on_wait);
    state.deferred_completion_id = 0u;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_WAIT, &sync_wait) == 0);
    execute.syncobj_stride = 0u;
    execute.num_in_syncobjs = 0u;
    execute.in_syncobjs = 0u;
    execute.num_out_syncobjs = 0u;
    execute.out_syncobjs = 0u;

    state.defer_submission = 1u;
    execute.flags = 2u;
    execute.fence_fd = -1;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execute) == 0);
    assert(execute.fence_fd == 72);
    assert(edge_virtgpu_sync_file_ready(g_sync_object) == 0);
    assert(state.deferred_completion_id != 0u);
    g_sync_notifications = 0u;
    edge_virtgpu_backend_submission_complete(
        state.deferred_completion_id, 0);
    assert(edge_virtgpu_sync_file_ready(g_sync_object) == 1);
    assert(g_sync_notifications == 1u);
    memset(&sync_info, 0, sizeof(sync_info));
    assert(test_sync_file_ioctl(
               g_sync_object, SYNC_IOC_FILE_INFO, &sync_info) == 0);
    assert(sync_info.status == 1 && sync_info.num_fences == 1u);
    assert(strcmp(sync_info.name, "edgeos-virtgpu") == 0);
    memset(&fence_info, 0, sizeof(fence_info));
    sync_info.num_fences = 1u;
    sync_info.sync_fence_info = (uint64_t)(uintptr_t)&fence_info;
    assert(test_sync_file_ioctl(
               g_sync_object, SYNC_IOC_FILE_INFO, &sync_info) == 0);
    assert(fence_info.status == 1 && fence_info.timestamp_ns != 0u);
    assert(strcmp(fence_info.driver_name, "virtio_gpu") == 0);
    memset(&sync_deadline, 0, sizeof(sync_deadline));
    sync_deadline.deadline_ns = 123456789u;
    assert(test_sync_file_ioctl(
               g_sync_object, SYNC_IOC_SET_DEADLINE,
               &sync_deadline) == 0);
    sync_info.flags = 1u;
    assert(test_sync_file_ioctl(
               g_sync_object, SYNC_IOC_FILE_INFO, &sync_info) ==
           -EDGE_LINUX_EINVAL);
    state.defer_submission = 0u;
    execute.flags = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execute) == 0);
    assert(edge_virtgpu_sync_file_ready(g_sync_object) == 1);
    state.deferred_completion_id = 0u;
    assert(kernel_fd_close(execute.fence_fd) == 0);
    execute.flags = 0u;
    execute.fence_fd = 0;

    sync_destroy.handle = sync_import_target.handle;
    sync_destroy.pad = 0u;
    assert(test_syncobj_ioctl(
               importing_client, DRM_IOCTL_SYNCOBJ_DESTROY,
               &sync_destroy) == 0);
    sync_destroy.handle = sync_a.handle;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_DESTROY, &sync_destroy) == 0);
    sync_destroy.handle = sync_b.handle;
    assert(test_syncobj_ioctl(
               client, DRM_IOCTL_SYNCOBJ_DESTROY, &sync_destroy) == 0);

    memset(&prime, 0, sizeof(prime));
    prime.handle = create.bo_handle;
    prime.flags = DRM_RDWR | DRM_CLOEXEC;
    assert(test_ioctl(
               client, DRM_IOCTL_PRIME_HANDLE_TO_FD, &prime) == 0);
    assert(prime.fd == 71);
    memset(&imported, 0, sizeof(imported));
    imported.fd = prime.fd;
    assert(test_ioctl(
               client, DRM_IOCTL_PRIME_FD_TO_HANDLE, &imported) == 0);
    assert(imported.handle == create.bo_handle);
    memset(&cross_imported, 0, sizeof(cross_imported));
    cross_imported.fd = prime.fd;
    assert(test_ioctl(
               importing_client, DRM_IOCTL_PRIME_FD_TO_HANDLE,
               &cross_imported) == 0);
    assert(cross_imported.handle &&
           cross_imported.handle != create.bo_handle);
    memset(&info, 0, sizeof(info));
    info.bo_handle = cross_imported.handle;
    assert(test_ioctl(
               importing_client, DRM_IOCTL_VIRTGPU_RESOURCE_INFO,
               &info) == 0);
    assert(info.res_handle == create.res_handle && info.size == 8192u);
    assert(state.contexts_created == 2u);
    assert(state.resources_attached == 1u);
    {
        uint32_t producer_handle = create.bo_handle;
        uint32_t consumer_handle = cross_imported.handle;
        test_execbuffer_t producer_execute = execute;
        test_execbuffer_t consumer_execute = execute;

        producer_execute.bo_handles =
            (uint64_t)(uintptr_t)&producer_handle;
        consumer_execute.bo_handles =
            (uint64_t)(uintptr_t)&consumer_handle;
        state.defer_submission = 1u;
        g_allocation_submit_client = client;
        g_allocation_submit_execute = &producer_execute;
        g_allocation_submit_state = &state;
        g_complete_deferred_on_wait = 1u;
        g_submit_foreign_on_allocation = 1u;
        assert(test_ioctl(
                   importing_client, DRM_IOCTL_VIRTGPU_EXECBUFFER,
                   &consumer_execute) == 0);
        assert(!g_submit_foreign_on_allocation);
        assert(!g_wait_completion_id && !g_complete_deferred_on_wait);
        state.deferred_completion_id = 0u;
        g_allocation_submit_client = 0u;
        g_allocation_submit_execute = NULL;
        g_allocation_submit_state = NULL;
    }
    handles[0] = create.bo_handle;
    state.defer_submission = 1u;
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execute) == 0);
    assert(state.deferred_completion_id != 0u);
    g_wait_completion_id = state.deferred_completion_id;
    g_complete_deferred_on_wait = 1u;
    state.defer_submission = 0u;
    handles[0] = cross_imported.handle;
    assert(test_ioctl(
               importing_client, DRM_IOCTL_VIRTGPU_EXECBUFFER,
               &execute) == 0);
    assert(!g_wait_completion_id && !g_complete_deferred_on_wait);
    state.deferred_completion_id = 0u;
    handles[0] = create.bo_handle;
    edge_virtgpu_release_client(importing_client);
    assert(state.resources_detached == 1u);
    assert(state.resources_destroyed == 1u);

    close.handle = create.bo_handle;
    close.pad = 0;
    assert(test_ioctl(client, DRM_IOCTL_GEM_CLOSE, &close) == 0);
    assert(state.resources_destroyed == 1u);
    assert(test_ioctl(
               client, DRM_IOCTL_PRIME_FD_TO_HANDLE, &imported) == 0);
    assert(imported.handle == create.bo_handle);
    close.handle = imported.handle;
    assert(test_ioctl(client, DRM_IOCTL_GEM_CLOSE, &close) == 0);
    assert(kernel_fd_close(prime.fd) == 0);
    assert(state.resources_destroyed == 1u);
    assert(edge_virtgpu_framebuffer_present(
               client, create.bo_handle,
               0u, 0u, 64u, 32u) == 0);
    edge_virtgpu_framebuffer_release(client, create.bo_handle);
    assert(state.resources_destroyed == 2u);
    edge_virtgpu_release_client(client);
    assert(state.contexts_destroyed == 2u);
    assert(state.transfers_to == 1u && state.transfers_from == 1u);
    assert(state.submissions == 10u);
    assert(state.presents == 3u);
    edge_virtgpu_backend_unregister(&owner);
    assert(!edge_virtgpu_available());
    puts("virtgpu_runtime_unit: PASS");
    return 0;
}
