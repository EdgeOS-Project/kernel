/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux virtgpu render ABI for EdgeOS. */

#ifndef EDGEOS_KERNEL_VIRTGPU_RUNTIME_H
#define EDGEOS_KERNEL_VIRTGPU_RUNTIME_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"

#define EDGE_VIRTGPU_RENDER_PATH "/dev/dri/renderD128"

#define EDGE_VIRTGPU_BACKEND_VIRGL             (1u << 0)
#define EDGE_VIRTGPU_BACKEND_CAPSET_QUERY_FIX  (1u << 1)
#define EDGE_VIRTGPU_BACKEND_CONTEXT_INIT      (1u << 2)
#define EDGE_VIRTGPU_BACKEND_RESOURCE_BLOB     (1u << 3)
#define EDGE_VIRTGPU_BACKEND_HOST_VISIBLE      (1u << 4)
#define EDGE_VIRTGPU_BACKING_SEGMENT_MAX       256u

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
    uint32_t size;
    uint32_t stride;
} edge_virtgpu_resource_create_t;

typedef struct {
    void *address;
    uint32_t page_count;
    uint32_t reserved;
} edge_virtgpu_backing_segment_t;

typedef struct {
    const edge_virtgpu_backing_segment_t *segments;
    uint32_t segment_count;
    uint32_t page_count;
} edge_virtgpu_backing_t;

typedef struct {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
    uint32_t level;
    uint64_t offset;
    uint32_t stride;
    uint32_t layer_stride;
} edge_virtgpu_transfer_t;

typedef struct {
    uint32_t flags;
    uint64_t supported_capsets;
    uint32_t maximum_command_size;
    uint32_t maximum_capset_size;
} edge_virtgpu_backend_info_t;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t size;
} edge_virtgpu_framebuffer_info_t;

typedef struct {
    int (*context_create)(void *context, uint32_t context_id,
                          uint32_t capset_id, const char *name);
    int (*context_destroy)(void *context, uint32_t context_id);
    int (*resource_create)(void *context, uint32_t context_id,
                           uint32_t resource_id,
                           const edge_virtgpu_resource_create_t *create,
                           const edge_virtgpu_backing_t *backing,
                           uint64_t size);
    int (*resource_destroy)(void *context, uint32_t context_id,
                            uint32_t resource_id);
    int (*resource_attach)(void *context, uint32_t context_id,
                           uint32_t resource_id);
    int (*resource_detach)(void *context, uint32_t context_id,
                           uint32_t resource_id);
    int (*transfer_to_host)(void *context, uint32_t context_id,
                            uint32_t resource_id,
                            const edge_virtgpu_transfer_t *transfer);
    int (*transfer_from_host)(void *context, uint32_t context_id,
                              uint32_t resource_id,
                              const edge_virtgpu_transfer_t *transfer);
    int (*submit_3d)(void *context, uint32_t context_id,
                     const void *commands, uint32_t size,
                     uint64_t completion_id);
    int (*get_capset)(void *context, uint32_t capset_id,
                      uint32_t version, void *data, uint32_t size,
                      uint32_t *actual_size);
    int (*present_resource)(void *context, uint32_t resource_id,
                            uint32_t resource_width,
                            uint32_t resource_height,
                            uint32_t x, uint32_t y,
                            uint32_t width, uint32_t height);
} edge_virtgpu_backend_operations_t;

typedef struct {
    const char *name;
    void *owner;
    void *context;
    edge_virtgpu_backend_info_t info;
    edge_virtgpu_backend_operations_t operations;
} edge_virtgpu_backend_t;

int edge_virtgpu_backend_register(const edge_virtgpu_backend_t *backend);
void edge_virtgpu_backend_unregister(void *owner);
int edge_virtgpu_available(void);
int edge_virtgpu_framebuffer_available(void);
const char *edge_virtgpu_driver_name(void);

int64_t edge_virtgpu_ioctl(uint64_t client_identity,
                           const kernel_ioctl_request_t *request);
int64_t edge_virtgpu_syncobj_ioctl(
    uint64_t client_identity, const kernel_ioctl_request_t *request);
void edge_virtgpu_release_client(uint64_t client_identity);
int edge_virtgpu_prime_retain(int32_t object_id);
void edge_virtgpu_prime_release(int32_t object_id);
int edge_virtgpu_sync_file_retain(int32_t object_id);
void edge_virtgpu_sync_file_release(int32_t object_id);
void edge_virtgpu_backend_submission_complete(
    uint64_t completion_id, int status);
int edge_virtgpu_sync_file_ready(int32_t object_id);
int64_t edge_virtgpu_sync_file_ioctl(
    int32_t object_id, const kernel_ioctl_request_t *request);
int edge_virtgpu_framebuffer_acquire(
    uint64_t client_identity, uint32_t handle,
    edge_virtgpu_framebuffer_info_t *info);
void edge_virtgpu_framebuffer_release(
    uint64_t client_identity, uint32_t handle);
int edge_virtgpu_framebuffer_present(
    uint64_t client_identity, uint32_t handle,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height);
int edge_virtgpu_framebuffer_reset(void);
int edge_virtgpu_mmap_prepare(uint64_t client_identity, uint64_t offset,
                              uint64_t length, uint32_t *page_count);
int edge_virtgpu_mmap_page(uint64_t client_identity, uint64_t offset,
                           uint32_t page_index, void **kernel_address);

#endif
