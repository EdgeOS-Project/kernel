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
    void *storage;
    uint64_t storage_size;
} test_backend_state_t;

static int test_context_create(void *context, uint32_t context_id,
                               uint32_t capset_id, const char *name) {
    test_backend_state_t *state = context;
    assert(name &&
           (strcmp(name, "renderer-unit") == 0 ||
            strcmp(name, "edgeos-virtgpu") == 0));
    state->contexts_created++;
    state->context_id = context_id;
    state->capset_id = capset_id;
    return 0;
}

static int test_context_destroy(void *context, uint32_t context_id) {
    test_backend_state_t *state = context;
    assert(context_id);
    state->contexts_destroyed++;
    return 0;
}

static int test_resource_create(
    void *context, uint32_t context_id, uint32_t resource_id,
    const edge_virtgpu_resource_create_t *create,
    void *storage, uint64_t size) {
    test_backend_state_t *state = context;
    assert(context_id == state->context_id);
    assert(create && create->width == 64u && create->height == 32u);
    assert(storage && size == 8192u);
    state->resources_created++;
    state->resource_id = resource_id;
    state->resource_context_id = context_id;
    state->storage = storage;
    state->storage_size = size;
    return 0;
}

static int test_resource_destroy(
    void *context, uint32_t context_id, uint32_t resource_id) {
    test_backend_state_t *state = context;
    assert(context_id == state->resource_context_id);
    assert(resource_id == state->resource_id);
    state->resources_destroyed++;
    return 0;
}

static int test_resource_attach(
    void *context, uint32_t context_id, uint32_t resource_id) {
    test_backend_state_t *state = context;
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
    const void *commands, uint32_t size) {
    static const uint8_t expected[] = { 1u, 2u, 3u, 4u };
    test_backend_state_t *state = context;
    assert(context_id == state->context_id);
    assert(size == sizeof(expected));
    assert(memcmp(commands, expected, sizeof(expected)) == 0);
    state->submissions++;
    return 0;
}

static int test_get_capset(
    void *context, uint32_t capset_id, uint32_t version,
    void *data, uint32_t size, uint32_t *actual_size) {
    (void)context;
    assert(capset_id == 2u);
    assert(version == 1u);
    assert(size == 16u);
    memset(data, 0x5au, size);
    *actual_size = size;
    return 0;
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    void *memory = 0;
    if (posix_memalign(&memory, 4096u, (size_t)page_count * 4096u) != 0)
        return 0;
    memset(memory, 0, (size_t)page_count * 4096u);
    return memory;
}

void arch_vm_free_page(void *page) {
    (void)page;
}

static int32_t g_prime_descriptor = -1;
static int32_t g_prime_object = -1;

int kernel_anonymous_fd_install_descriptor(
    kernel_anonymous_fd_kind_t kind, int32_t object_id,
    uint32_t status_flags, uint32_t descriptor_flags) {
    assert(kind == KERNEL_ANONYMOUS_FD_PRIME);
    assert(object_id > 0);
    assert(status_flags == DRM_RDWR);
    assert(descriptor_flags == DRM_CLOEXEC);
    assert(g_prime_descriptor < 0);
    g_prime_descriptor = 71;
    g_prime_object = object_id;
    return g_prime_descriptor;
}

int kernel_anonymous_fd_descriptor_object_id(
    int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    if (kind != KERNEL_ANONYMOUS_FD_PRIME ||
        descriptor != g_prime_descriptor)
        return -EDGE_LINUX_EBADF;
    return g_prime_object;
}

int kernel_fd_close(int32_t descriptor) {
    if (descriptor != g_prime_descriptor)
        return -EDGE_LINUX_EBADF;
    edge_virtgpu_prime_release(g_prime_object);
    g_prime_descriptor = -1;
    g_prime_object = -1;
    return 0;
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
    uint32_t pages;
    void *first_page = 0;
    void *second_page = 0;

    assert(edge_virtgpu_backend_register(&backend) == 0);
    assert(edge_virtgpu_available());
    assert(strcmp(edge_virtgpu_driver_name(), "virtio_gpu") == 0);
    assert(test_ioctl(client, DRM_IOCTL_VERSION, &version) == 0);
    assert(version.major == 0);
    assert(version.minor == 0);
    assert(version.patch == 0);
    assert(strcmp(name, "virtio_gpu") == 0);
    assert(test_ioctl(client, DRM_IOCTL_GET_CAP, &prime_capability) == 0);
    assert(prime_capability.value ==
           (EDGE_DRM_PRIME_CAP_IMPORT | EDGE_DRM_PRIME_CAP_EXPORT));
    assert(test_ioctl(client, DRM_IOCTL_GET_CAP,
                      &unsupported_capability) == -EDGE_LINUX_EINVAL);
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_GETPARAM, &parameter) == 0);
    assert(parameter_value == 1u);
    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_GET_CAPS, &get_caps) == 0);
    for (uint32_t index = 0; index < sizeof(capabilities); ++index)
        assert(capabilities[index] == 0x5au);

    assert(test_ioctl(client, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &context) == 0);
    assert(state.contexts_created == 1u && state.capset_id == 2u);
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
    edge_virtgpu_release_client(importing_client);
    assert(state.resources_detached == 1u);
    assert(state.resources_destroyed == 0u);

    close.handle = create.bo_handle;
    close.pad = 0;
    assert(test_ioctl(client, DRM_IOCTL_GEM_CLOSE, &close) == 0);
    assert(state.resources_destroyed == 0u);
    assert(test_ioctl(
               client, DRM_IOCTL_PRIME_FD_TO_HANDLE, &imported) == 0);
    assert(imported.handle == create.bo_handle);
    close.handle = imported.handle;
    assert(test_ioctl(client, DRM_IOCTL_GEM_CLOSE, &close) == 0);
    assert(kernel_fd_close(prime.fd) == 0);
    assert(state.resources_destroyed == 0u);
    assert(edge_virtgpu_framebuffer_present(
               client, create.bo_handle,
               0u, 0u, 64u, 32u) == 0);
    edge_virtgpu_framebuffer_release(client, create.bo_handle);
    assert(state.resources_destroyed == 1u);
    edge_virtgpu_release_client(client);
    assert(state.contexts_destroyed == 2u);
    assert(state.transfers_to == 1u && state.transfers_from == 1u);
    assert(state.submissions == 1u);
    assert(state.presents == 2u);
    edge_virtgpu_backend_unregister(&owner);
    assert(!edge_virtgpu_available());
    puts("virtgpu_runtime_unit: PASS");
    return 0;
}
