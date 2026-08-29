/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent Linux virtgpu render ABI.
 *
 * The public layouts and ioctl numbers follow the MIT-licensed virtgpu DRM
 * UAPI. Device transport is supplied by a registered EdgeOS backend.
 */

#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "kernel/anonymous_fd.h"
#include "kernel/drm_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/fd_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/virtgpu_runtime.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/boottime.h"

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
#define EDGE_DRM_IOCTL_SYNCOBJ_CREATE       0xc00864bfu
#define EDGE_DRM_IOCTL_SYNCOBJ_DESTROY      0xc00864c0u
#define EDGE_DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD 0xc01864c1u
#define EDGE_DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE 0xc01864c2u
#define EDGE_DRM_IOCTL_SYNCOBJ_WAIT         0xc02864c3u
#define EDGE_DRM_IOCTL_SYNCOBJ_RESET        0xc01064c4u
#define EDGE_DRM_IOCTL_SYNCOBJ_SIGNAL       0xc01064c5u
#define EDGE_DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT 0xc03064cau
#define EDGE_DRM_IOCTL_SYNCOBJ_QUERY        0xc01864cbu
#define EDGE_DRM_IOCTL_SYNCOBJ_TRANSFER     0xc02064ccu
#define EDGE_DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL 0xc01864cdu
#define EDGE_DRM_IOCTL_SYNCOBJ_EVENTFD      0xc01864cfu
#define EDGE_SYNC_IOC_MERGE                 0xc0303e03u
#define EDGE_SYNC_IOC_FILE_INFO             0xc0383e04u
#define EDGE_SYNC_IOC_SET_DEADLINE          0x40103e05u

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
#define EDGE_VIRTGPU_EXECBUF_SYNCOBJ_RESET 0x01u
#define EDGE_VIRTGPU_WAIT_NOWAIT          0x01u
#define EDGE_VIRTGPU_PRIME_RDWR           0x00000002u
#define EDGE_VIRTGPU_PRIME_CLOEXEC        0x00080000u
#define EDGE_VIRTGPU_PRIME_FLAGS          \
    (EDGE_VIRTGPU_PRIME_RDWR | EDGE_VIRTGPU_PRIME_CLOEXEC)
#define EDGE_DRM_SYNCOBJ_CREATE_SIGNALED 0x01u
#define EDGE_DRM_SYNCOBJ_WAIT_ALL 0x01u
#define EDGE_DRM_SYNCOBJ_WAIT_FOR_SUBMIT 0x02u
#define EDGE_DRM_SYNCOBJ_WAIT_AVAILABLE 0x04u
#define EDGE_DRM_SYNCOBJ_WAIT_DEADLINE 0x08u
#define EDGE_DRM_SYNCOBJ_WAIT_FLAGS 0x0fu
#define EDGE_DRM_SYNCOBJ_QUERY_LAST_SUBMITTED 0x01u
#define EDGE_DRM_SYNCOBJ_HANDLE_EXPORT_SYNC_FILE 0x01u
#define EDGE_DRM_SYNCOBJ_HANDLE_TIMELINE 0x02u
#define EDGE_DRM_SYNCOBJ_HANDLE_IMPORT_SYNC_FILE 0x01u

#define EDGE_VIRTGPU_PAGE_SIZE          4096u
#define EDGE_VIRTGPU_CLIENT_COUNT       64u
#define EDGE_VIRTGPU_RESOURCE_COUNT     4096u
#define EDGE_VIRTGPU_EXEC_HANDLE_COUNT  256u
#define EDGE_VIRTGPU_CONTEXT_PARAM_COUNT 16u
#define EDGE_VIRTGPU_MAX_RESOURCE_SIZE  (256ull * 1024ull * 1024ull)
#define EDGE_VIRTGPU_MAX_COMMAND_SIZE   (4u * 1024u * 1024u)
#define EDGE_VIRTGPU_MAX_CAPSET_SIZE    (256u * 1024u)
#define EDGE_VIRTGPU_MAP_BASE           0x100000000ull
#define EDGE_VIRTGPU_SYNCOBJ_COUNT      512u
#define EDGE_VIRTGPU_SYNCOBJ_HANDLE_COUNT 2048u
#define EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT 256u
#define EDGE_VIRTGPU_SYNC_FILE_COUNT    1024u
#define EDGE_VIRTGPU_SYNCOBJ_EVENT_COUNT 1024u
#define EDGE_VIRTGPU_SYNCOBJ_TRANSFER_COUNT 1024u
#define EDGE_VIRTGPU_SUBMISSION_COUNT   256u

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
    uint32_t handle;
    uint32_t flags;
    uint64_t point;
} edge_virtgpu_execbuffer_syncobj_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
} edge_virtgpu_syncobj_create_t;

typedef struct {
    uint32_t handle;
    uint32_t pad;
} edge_virtgpu_syncobj_destroy_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    int32_t fd;
    uint32_t pad;
    uint64_t point;
} edge_virtgpu_syncobj_handle_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    uint64_t point;
    int32_t fd;
    uint32_t pad;
} edge_virtgpu_syncobj_eventfd_t;

typedef struct {
    uint64_t handles;
    int64_t timeout_ns;
    uint32_t count_handles;
    uint32_t flags;
    uint32_t first_signaled;
    uint32_t pad;
    uint64_t deadline_ns;
} edge_virtgpu_syncobj_wait_t;

typedef struct {
    uint64_t handles;
    uint64_t points;
    int64_t timeout_ns;
    uint32_t count_handles;
    uint32_t flags;
    uint32_t first_signaled;
    uint32_t pad;
    uint64_t deadline_ns;
} edge_virtgpu_syncobj_timeline_wait_t;

typedef struct {
    uint64_t handles;
    uint32_t count_handles;
    uint32_t pad;
} edge_virtgpu_syncobj_array_t;

typedef struct {
    uint64_t handles;
    uint64_t points;
    uint32_t count_handles;
    uint32_t flags;
} edge_virtgpu_syncobj_timeline_array_t;

typedef struct {
    uint32_t source_handle;
    uint32_t destination_handle;
    uint64_t source_point;
    uint64_t destination_point;
    uint32_t flags;
    uint32_t pad;
} edge_virtgpu_syncobj_transfer_t;

typedef struct {
    uint8_t used;
    uint8_t signaled;
    uint16_t references;
    uint64_t point;
    uint64_t available_point;
    uint64_t signal_timestamp_ns;
} edge_virtgpu_syncobj_t;

typedef struct {
    uint8_t used;
    uint8_t pad[3];
    uint64_t owner;
    uint32_t handle;
    uint32_t object_id;
} edge_virtgpu_syncobj_handle_record_t;

typedef struct {
    uint8_t used;
    uint8_t sync_file;
    uint16_t references;
    uint32_t object_id;
    uint64_t point;
    uint64_t deadline_ns;
    uint32_t leaf_count;
    int32_t components[2];
    char name[32];
} edge_virtgpu_sync_file_t;

typedef struct {
    char name[32];
    int32_t fd2;
    int32_t fence;
    uint32_t flags;
    uint32_t pad;
} edge_sync_merge_data_t;

typedef struct {
    char obj_name[32];
    char driver_name[32];
    int32_t status;
    uint32_t flags;
    uint64_t timestamp_ns;
} edge_sync_fence_info_t;

typedef struct {
    char name[32];
    int32_t status;
    uint32_t flags;
    uint32_t num_fences;
    uint32_t pad;
    uint64_t sync_fence_info;
} edge_sync_file_info_t;

typedef struct {
    uint64_t deadline_ns;
    uint64_t pad;
} edge_sync_set_deadline_t;

typedef struct {
    uint8_t used;
    uint8_t available;
    uint16_t pad;
    uint32_t object_id;
    uint64_t point;
    int32_t event_id;
    uint32_t owner_handle;
    uint64_t owner;
} edge_virtgpu_syncobj_event_t;

typedef struct {
    uint8_t used;
    uint8_t pad[3];
    uint32_t source_object_id;
    uint32_t destination_object_id;
    uint64_t source_point;
    uint64_t destination_point;
} edge_virtgpu_syncobj_transfer_record_t;

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
    uint8_t context_creating;
    uint8_t file_released;
    uint8_t pad[4];
    uint64_t identity;
    uint32_t context_id;
    uint32_t capset_id;
    char debug_name[64];
} edge_virtgpu_client_t;

typedef struct {
    uint8_t used;
    uint8_t handle_open;
    uint8_t backend_ready;
    uint8_t backend_creating;
    uint16_t framebuffer_refs;
    uint32_t prime_refs;
    uint32_t alias_refs;
    uint32_t submission_refs;
    uint32_t wait_refs;
    uint32_t present_refs;
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
    edge_virtgpu_backing_t backing;
} edge_virtgpu_resource_t;

typedef struct {
    uint8_t used;
    uint8_t pad[3];
    uint32_t context_id;
    uint64_t completion_id;
    uint8_t *commands;
    uint32_t command_pages;
    uint8_t *syncobj_storage;
    uint32_t syncobj_pages;
    edge_virtgpu_execbuffer_syncobj_t *outputs;
    uint32_t output_count;
    uint32_t output_fence_object_id;
    uint32_t resource_object_ids[EDGE_VIRTGPU_EXEC_HANDLE_COUNT];
    uint32_t resource_count;
} edge_virtgpu_submission_t;

typedef struct {
    uint8_t used;
    uint8_t pad[3];
    uint32_t resource_object_id;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} edge_virtgpu_pending_present_t;

_Static_assert(sizeof(edge_virtgpu_version_t) == 64,
               "Linux DRM version layout mismatch");
_Static_assert(sizeof(edge_virtgpu_execbuffer_t) == 64,
               "Linux virtgpu execbuffer layout mismatch");
_Static_assert(sizeof(edge_virtgpu_execbuffer_syncobj_t) == 16,
               "Linux virtgpu execbuffer syncobj layout mismatch");
_Static_assert(sizeof(edge_virtgpu_resource_create_uapi_t) == 56,
               "Linux virtgpu resource create layout mismatch");
_Static_assert(sizeof(edge_virtgpu_transfer_uapi_t) == 44,
               "Linux virtgpu transfer layout mismatch");
_Static_assert(sizeof(edge_virtgpu_get_caps_t) == 24,
               "Linux virtgpu capset layout mismatch");
_Static_assert(sizeof(edge_virtgpu_prime_handle_t) == 12,
               "Linux DRM PRIME handle layout mismatch");
_Static_assert(sizeof(edge_virtgpu_syncobj_wait_t) == 40,
               "Linux DRM syncobj wait layout mismatch");
_Static_assert(sizeof(edge_virtgpu_syncobj_timeline_wait_t) == 48,
               "Linux DRM timeline wait layout mismatch");
_Static_assert(sizeof(edge_virtgpu_syncobj_handle_t) == 24,
               "Linux DRM syncobj handle layout mismatch");
_Static_assert(sizeof(edge_virtgpu_syncobj_eventfd_t) == 24,
               "Linux DRM syncobj eventfd layout mismatch");
_Static_assert(sizeof(edge_sync_merge_data_t) == 48,
               "Linux sync merge layout mismatch");
_Static_assert(sizeof(edge_sync_fence_info_t) == 80,
               "Linux sync fence info layout mismatch");
_Static_assert(sizeof(edge_sync_file_info_t) == 56,
               "Linux sync file info layout mismatch");
_Static_assert(sizeof(edge_sync_set_deadline_t) == 16,
               "Linux sync deadline layout mismatch");

static edge_virtgpu_backend_t g_edge_virtgpu_backend;
static edge_virtgpu_client_t
    g_edge_virtgpu_clients[EDGE_VIRTGPU_CLIENT_COUNT];
static edge_virtgpu_resource_t
    g_edge_virtgpu_resources[EDGE_VIRTGPU_RESOURCE_COUNT];
static edge_virtgpu_syncobj_t
    g_edge_virtgpu_syncobjs[EDGE_VIRTGPU_SYNCOBJ_COUNT];
static edge_virtgpu_syncobj_handle_record_t
    g_edge_virtgpu_syncobj_handles[EDGE_VIRTGPU_SYNCOBJ_HANDLE_COUNT];
static edge_virtgpu_sync_file_t
    g_edge_virtgpu_sync_files[EDGE_VIRTGPU_SYNC_FILE_COUNT];
static int32_t
    g_edge_virtgpu_sync_walk[EDGE_VIRTGPU_SYNC_FILE_COUNT];
static edge_virtgpu_syncobj_event_t
    g_edge_virtgpu_syncobj_events[EDGE_VIRTGPU_SYNCOBJ_EVENT_COUNT];
static edge_virtgpu_syncobj_transfer_record_t
    g_edge_virtgpu_syncobj_transfers[EDGE_VIRTGPU_SYNCOBJ_TRANSFER_COUNT];
static edge_virtgpu_submission_t
    g_edge_virtgpu_submissions[EDGE_VIRTGPU_SUBMISSION_COUNT];
static edge_virtgpu_pending_present_t g_edge_virtgpu_pending_present;
static volatile unsigned int g_edge_virtgpu_guard;
static volatile unsigned int g_edge_virtgpu_cleanup_guard;
static uint32_t g_edge_virtgpu_next_context = 1u;
static uint32_t g_edge_virtgpu_next_handle = 1u;
static uint32_t g_edge_virtgpu_next_resource = 2u;
static uint64_t g_edge_virtgpu_next_map = EDGE_VIRTGPU_MAP_BASE;
static uint32_t g_edge_virtgpu_next_syncobj_handle = 1u;
static uint64_t g_edge_virtgpu_next_completion_id = 1u;
static volatile uint64_t g_edge_virtgpu_sync_sequence;

typedef enum {
    EDGE_VIRTGPU_CLEANUP_RESOURCE_DESTROY = 1,
    EDGE_VIRTGPU_CLEANUP_RESOURCE_DETACH,
    EDGE_VIRTGPU_CLEANUP_CONTEXT_DESTROY,
} edge_virtgpu_cleanup_kind_t;

typedef struct {
    edge_virtgpu_cleanup_kind_t kind;
    void *backend_context;
    int (*resource_operation)(void *, uint32_t, uint32_t);
    int (*context_operation)(void *, uint32_t);
    uint32_t context_id;
    uint32_t resource_id;
    edge_virtgpu_backing_t backing;
} edge_virtgpu_cleanup_t;

#define EDGE_VIRTGPU_CLEANUP_COUNT \
    (EDGE_VIRTGPU_RESOURCE_COUNT * 2u + EDGE_VIRTGPU_CLIENT_COUNT)

static edge_virtgpu_cleanup_t
    g_edge_virtgpu_cleanup[EDGE_VIRTGPU_CLEANUP_COUNT];
static uint32_t g_edge_virtgpu_cleanup_head;
static uint32_t g_edge_virtgpu_cleanup_tail;
static uint32_t g_edge_virtgpu_cleanup_count;

static void edge_virtgpu_cleanup_drain(void);

static void edge_virtgpu_relax(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void edge_virtgpu_lock_raw(void) {
    while (__atomic_test_and_set(
               &g_edge_virtgpu_guard, __ATOMIC_ACQUIRE))
        if (!kernel_runtime_yield()) edge_virtgpu_relax();
}

static void edge_virtgpu_unlock_raw(void) {
    __atomic_clear(&g_edge_virtgpu_guard, __ATOMIC_RELEASE);
}

static void edge_virtgpu_lock(void) {
    edge_virtgpu_lock_raw();
}

static void edge_virtgpu_unlock(void) {
    edge_virtgpu_unlock_raw();
    edge_virtgpu_cleanup_drain();
}

static int edge_virtgpu_cleanup_enqueue_locked(
    const edge_virtgpu_cleanup_t *cleanup) {
    if (!cleanup ||
        g_edge_virtgpu_cleanup_count >= EDGE_VIRTGPU_CLEANUP_COUNT)
        return -1;
    g_edge_virtgpu_cleanup[g_edge_virtgpu_cleanup_tail] = *cleanup;
    g_edge_virtgpu_cleanup_tail =
        (g_edge_virtgpu_cleanup_tail + 1u) %
        EDGE_VIRTGPU_CLEANUP_COUNT;
    g_edge_virtgpu_cleanup_count++;
    return 0;
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

static edge_virtgpu_syncobj_handle_record_t *
edge_virtgpu_syncobj_handle_locked(uint64_t owner, uint32_t handle)
{
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNCOBJ_HANDLE_COUNT; ++index) {
        edge_virtgpu_syncobj_handle_record_t *record =
            &g_edge_virtgpu_syncobj_handles[index];

        if (record->used && record->owner == owner &&
            record->handle == handle)
            return record;
    }
    return NULL;
}

static edge_virtgpu_syncobj_t *
edge_virtgpu_syncobj_object_locked(uint32_t object_id)
{
    if (!object_id || object_id > EDGE_VIRTGPU_SYNCOBJ_COUNT ||
        !g_edge_virtgpu_syncobjs[object_id - 1u].used)
        return NULL;
    return &g_edge_virtgpu_syncobjs[object_id - 1u];
}

static edge_virtgpu_syncobj_t *
edge_virtgpu_syncobj_locked(uint64_t owner, uint32_t handle)
{
    edge_virtgpu_syncobj_handle_record_t *record =
        edge_virtgpu_syncobj_handle_locked(owner, handle);

    return record ? edge_virtgpu_syncobj_object_locked(record->object_id) :
        NULL;
}

static int edge_virtgpu_syncobj_object_ready_locked(
    uint32_t object_id, uint64_t point, int available)
{
    edge_virtgpu_syncobj_t *object =
        edge_virtgpu_syncobj_object_locked(object_id);

    if (!object) return -EDGE_LINUX_EINVAL;
    if (!point)
        return available ? object->available_point != 0u :
            object->signaled != 0u;
    return available ? object->available_point >= point :
        object->point >= point;
}

static void edge_virtgpu_syncobj_release_object_locked(uint32_t object_id);

static void edge_virtgpu_syncobj_notify_locked(uint32_t object_id)
{
    int progress;

    (void)object_id;
    do {
        progress = 0;
        for (uint32_t index = 0;
             index < EDGE_VIRTGPU_SYNCOBJ_TRANSFER_COUNT; ++index) {
            edge_virtgpu_syncobj_transfer_record_t *transfer =
                &g_edge_virtgpu_syncobj_transfers[index];
            edge_virtgpu_syncobj_t *destination;
            uint32_t source_object_id;
            uint32_t destination_object_id;

            if (!transfer->used ||
                edge_virtgpu_syncobj_object_ready_locked(
                    transfer->source_object_id,
                    transfer->source_point, 0) <= 0)
                continue;
            destination = edge_virtgpu_syncobj_object_locked(
                transfer->destination_object_id);
            if (destination) {
                uint64_t point = transfer->destination_point ?
                    transfer->destination_point : 1u;
                if (point > destination->available_point)
                    destination->available_point = point;
                if (point > destination->point)
                    destination->point = point;
                destination->signaled = 1u;
                if (!destination->signal_timestamp_ns)
                    destination->signal_timestamp_ns =
                        boottime_monotonic_us() * 1000u;
            }
            source_object_id = transfer->source_object_id;
            destination_object_id = transfer->destination_object_id;
            memset(transfer, 0, sizeof(*transfer));
            edge_virtgpu_syncobj_release_object_locked(source_object_id);
            edge_virtgpu_syncobj_release_object_locked(
                destination_object_id);
            progress = 1;
        }
    } while (progress);

    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNCOBJ_EVENT_COUNT; ++index) {
        edge_virtgpu_syncobj_event_t *event =
            &g_edge_virtgpu_syncobj_events[index];

        if (!event->used ||
            edge_virtgpu_syncobj_object_ready_locked(
                event->object_id, event->point, event->available) <= 0)
            continue;
        (void)kernel_eventfd_write_value(event->event_id, 1, 1u);
        kernel_eventfd_release(event->event_id);
        memset(event, 0, sizeof(*event));
    }
    (void)__atomic_add_fetch(
        &g_edge_virtgpu_sync_sequence, 1u, __ATOMIC_RELEASE);
    kernel_runtime_notify_sequence(&g_edge_virtgpu_sync_sequence);
}

static uint32_t edge_virtgpu_syncobj_next_handle_locked(uint64_t owner)
{
    for (uint32_t attempt = 0;
         attempt < EDGE_VIRTGPU_SYNCOBJ_HANDLE_COUNT + 1u; ++attempt) {
        uint32_t handle = g_edge_virtgpu_next_syncobj_handle++;

        if (!handle) handle = g_edge_virtgpu_next_syncobj_handle++;
        if (!edge_virtgpu_syncobj_handle_locked(owner, handle))
            return handle;
    }
    return 0u;
}

static int edge_virtgpu_syncobj_add_handle_locked(
    uint64_t owner, uint32_t object_id, uint32_t *handle)
{
    edge_virtgpu_syncobj_t *object =
        edge_virtgpu_syncobj_object_locked(object_id);

    if (!owner || !object || !handle) return -EDGE_LINUX_EINVAL;
    if (object->references == UINT16_MAX) return -EDGE_LINUX_EOVERFLOW;
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNCOBJ_HANDLE_COUNT; ++index) {
        edge_virtgpu_syncobj_handle_record_t *record =
            &g_edge_virtgpu_syncobj_handles[index];
        uint32_t next;

        if (record->used) continue;
        next = edge_virtgpu_syncobj_next_handle_locked(owner);
        if (!next) return -EDGE_LINUX_ENOSPC;
        memset(record, 0, sizeof(*record));
        record->used = 1u;
        record->owner = owner;
        record->handle = next;
        record->object_id = object_id;
        object->references++;
        *handle = next;
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

static void edge_virtgpu_syncobj_release_object_locked(uint32_t object_id)
{
    edge_virtgpu_syncobj_t *object =
        edge_virtgpu_syncobj_object_locked(object_id);

    if (!object) return;
    if (object->references) object->references--;
    if (!object->references) {
        for (uint32_t index = 0;
             index < EDGE_VIRTGPU_SYNCOBJ_EVENT_COUNT; ++index) {
            edge_virtgpu_syncobj_event_t *event =
                &g_edge_virtgpu_syncobj_events[index];

            if (!event->used || event->object_id != object_id) continue;
            kernel_eventfd_release(event->event_id);
            memset(event, 0, sizeof(*event));
        }
        memset(object, 0, sizeof(*object));
    }
}

static int edge_virtgpu_syncobj_remove_handle_locked(
    uint64_t owner, uint32_t handle)
{
    edge_virtgpu_syncobj_handle_record_t *record =
        edge_virtgpu_syncobj_handle_locked(owner, handle);
    uint32_t object_id;

    if (!record) return -EDGE_LINUX_EINVAL;
    object_id = record->object_id;
    memset(record, 0, sizeof(*record));
    edge_virtgpu_syncobj_release_object_locked(object_id);
    return 0;
}

static int edge_virtgpu_syncobj_create_locked(
    uint64_t owner, int signaled, uint32_t *handle)
{
    for (uint32_t index = 0; index < EDGE_VIRTGPU_SYNCOBJ_COUNT; ++index) {
        edge_virtgpu_syncobj_t *object = &g_edge_virtgpu_syncobjs[index];
        int result;

        if (object->used) continue;
        memset(object, 0, sizeof(*object));
        object->used = 1u;
        object->signaled = signaled ? 1u : 0u;
        object->point = signaled ? 1u : 0u;
        object->available_point = object->point;
        object->signal_timestamp_ns = signaled ?
            boottime_monotonic_us() * 1000u : 0u;
        result = edge_virtgpu_syncobj_add_handle_locked(
            owner, index + 1u, handle);
        if (result < 0) memset(object, 0, sizeof(*object));
        return result;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int edge_virtgpu_syncobj_point_ready_locked(
    uint64_t owner, uint32_t handle, uint64_t point, int available)
{
    edge_virtgpu_syncobj_t *object =
        edge_virtgpu_syncobj_locked(owner, handle);

    if (!object) return -EDGE_LINUX_EINVAL;
    if (!point)
        return available ? object->available_point != 0u :
            object->signaled != 0u;
    return available ? object->available_point >= point :
        object->point >= point;
}

static int edge_virtgpu_syncobj_signal_object_locked(
    uint32_t object_id, uint64_t point)
{
    edge_virtgpu_syncobj_t *object =
        edge_virtgpu_syncobj_object_locked(object_id);

    if (!object) return -EDGE_LINUX_EINVAL;
    if (!point) point = object->point ? object->point : 1u;
    if (point > object->available_point) object->available_point = point;
    if (point > object->point) object->point = point;
    object->signaled = 1u;
    if (!object->signal_timestamp_ns)
        object->signal_timestamp_ns = boottime_monotonic_us() * 1000u;
    edge_virtgpu_syncobj_notify_locked(object_id);
    return 0;
}

static int edge_virtgpu_syncobj_signal_locked(
    uint64_t owner, uint32_t handle, uint64_t point)
{
    edge_virtgpu_syncobj_handle_record_t *record =
        edge_virtgpu_syncobj_handle_locked(owner, handle);

    return record ? edge_virtgpu_syncobj_signal_object_locked(
                        record->object_id, point) :
                    -EDGE_LINUX_EINVAL;
}

static int edge_virtgpu_syncobj_reset_locked(
    uint64_t owner, uint32_t handle)
{
    edge_virtgpu_syncobj_t *object =
        edge_virtgpu_syncobj_locked(owner, handle);

    if (!object) return -EDGE_LINUX_EINVAL;
    object->signaled = 0u;
    object->point = 0u;
    object->available_point = 0u;
    object->signal_timestamp_ns = 0u;
    return 0;
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
    if (!resource || !resource->used || !resource->backend_ready) return 0;
    if (!resource->backing_object_id) return resource;
    resource = edge_virtgpu_prime_resource(
        resource->backing_object_id);
    return resource && resource->backend_ready &&
        !resource->backing_object_id ? resource : 0;
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
    void *backend_context;
    int (*context_create)(void *, uint32_t, uint32_t, const char *);
    uint64_t deadline_us;
    uint32_t context_id;
    uint32_t capset_id;
    char debug_name[sizeof(client->debug_name)];
    int result;

    if (!client) return -EDGE_LINUX_EINVAL;
    deadline_us = boottime_monotonic_us() + 15000000u;
    while (client->context_creating) {
        uint64_t observed_sequence = __atomic_load_n(
            &g_edge_virtgpu_sync_sequence, __ATOMIC_ACQUIRE);

        edge_virtgpu_unlock();
        result = kernel_runtime_wait_sequence(
            &g_edge_virtgpu_sync_sequence, observed_sequence,
            deadline_us);
        edge_virtgpu_lock();
        if (result < 0 || !client->used)
            return -EDGE_LINUX_EIO;
    }
    if (client->context_created) return 0;
    context_create = g_edge_virtgpu_backend.operations.context_create;
    backend_context = g_edge_virtgpu_backend.context;
    if (!context_create)
        return -EDGE_LINUX_EIO;
    client->context_creating = 1u;
    context_id = client->context_id;
    capset_id = client->capset_id;
    memcpy(debug_name, client->debug_name, sizeof(debug_name));

    edge_virtgpu_unlock();
    result = context_create(
        backend_context, context_id, capset_id, debug_name);
    edge_virtgpu_lock();
    if (!client->used || client->context_id != context_id)
        return -EDGE_LINUX_EIO;
    client->context_creating = 0u;
    if (result >= 0)
        client->context_created = 1u;
    (void)__atomic_add_fetch(
        &g_edge_virtgpu_sync_sequence, 1u, __ATOMIC_RELEASE);
    kernel_runtime_notify_sequence(&g_edge_virtgpu_sync_sequence);
    return result < 0 ? -EDGE_LINUX_EIO : 0;
}

static void edge_virtgpu_client_maybe_release(
    edge_virtgpu_client_t *client) {
    edge_virtgpu_cleanup_t cleanup;

    if (!client || !client->used || !client->file_released ||
        client->context_creating)
        return;
    for (uint32_t index = 0; index < EDGE_VIRTGPU_RESOURCE_COUNT; ++index)
        if (g_edge_virtgpu_resources[index].used &&
            g_edge_virtgpu_resources[index].context_id ==
                client->context_id)
            return;
    for (uint32_t index = 0; index < EDGE_VIRTGPU_SUBMISSION_COUNT; ++index)
        if (g_edge_virtgpu_submissions[index].used &&
            g_edge_virtgpu_submissions[index].context_id ==
                client->context_id)
            return;
    if (client->context_created &&
        g_edge_virtgpu_backend.operations.context_destroy) {
        memset(&cleanup, 0, sizeof(cleanup));
        cleanup.kind = EDGE_VIRTGPU_CLEANUP_CONTEXT_DESTROY;
        cleanup.backend_context = g_edge_virtgpu_backend.context;
        cleanup.context_operation =
            g_edge_virtgpu_backend.operations.context_destroy;
        cleanup.context_id = client->context_id;
        if (edge_virtgpu_cleanup_enqueue_locked(&cleanup) < 0)
            return;
    }
    memset(client, 0, sizeof(*client));
}

static void edge_virtgpu_storage_release(
    void *storage, uint32_t page_count) {
    for (uint32_t page = 0; storage && page < page_count; ++page)
        arch_vm_free_page(
            (uint8_t *)storage +
            (uint64_t)page * EDGE_VIRTGPU_PAGE_SIZE);
}

_Static_assert(
    sizeof(edge_virtgpu_backing_segment_t) *
            EDGE_VIRTGPU_BACKING_SEGMENT_MAX <=
        EDGE_VIRTGPU_PAGE_SIZE,
    "VirtGPU backing segment table must fit in one page");

static void edge_virtgpu_backing_release(
    const edge_virtgpu_backing_t *backing) {
    if (!backing || !backing->segments) return;
    for (uint32_t segment = 0; segment < backing->segment_count;
         ++segment) {
        const edge_virtgpu_backing_segment_t *entry =
            &backing->segments[segment];

        for (uint32_t page = 0; entry->address &&
             page < entry->page_count; ++page)
            arch_vm_free_page(
                (uint8_t *)entry->address +
                (uint64_t)page * EDGE_VIRTGPU_PAGE_SIZE);
    }
    arch_vm_free_page((void *)backing->segments);
}

static int edge_virtgpu_backing_allocate(
    uint32_t page_count, edge_virtgpu_backing_t *backing) {
    edge_virtgpu_backing_segment_t *segments;
    uint32_t remaining;
    uint32_t count = 0u;

    if (!page_count || !backing) return -1;
    memset(backing, 0, sizeof(*backing));
    segments = arch_vm_alloc_pages(1u);
    if (!segments) return -1;
    remaining = page_count;
    while (remaining) {
        uint32_t slots = EDGE_VIRTGPU_BACKING_SEGMENT_MAX - count;
        uint32_t minimum;
        uint32_t candidate;
        void *address = 0;

        if (!slots) goto fail;
        minimum = (remaining + slots - 1u) / slots;
        candidate = remaining < 1024u ? remaining : 1024u;
        if (candidate < minimum) candidate = minimum;
        for (;;) {
            address = arch_vm_alloc_pages(candidate);
            if (address || candidate == minimum) break;
            candidate /= 2u;
            if (candidate < minimum) candidate = minimum;
        }
        if (!address) goto fail;
        segments[count].address = address;
        segments[count].page_count = candidate;
        count++;
        remaining -= candidate;
    }
    backing->segments = segments;
    backing->segment_count = count;
    backing->page_count = page_count;
    return 0;

fail:
    {
        edge_virtgpu_backing_t partial = {
            .segments = segments,
            .segment_count = count,
            .page_count = page_count - remaining,
        };
        edge_virtgpu_backing_release(&partial);
    }
    return -1;
}

static void *edge_virtgpu_backing_page(
    const edge_virtgpu_backing_t *backing, uint32_t page_index) {
    if (!backing || !backing->segments ||
        page_index >= backing->page_count)
        return 0;
    for (uint32_t segment = 0; segment < backing->segment_count;
         ++segment) {
        const edge_virtgpu_backing_segment_t *entry =
            &backing->segments[segment];

        if (page_index < entry->page_count)
            return (uint8_t *)entry->address +
                (uint64_t)page_index * EDGE_VIRTGPU_PAGE_SIZE;
        page_index -= entry->page_count;
    }
    return 0;
}

static void edge_virtgpu_cleanup_drain(void) {
    edge_virtgpu_cleanup_t cleanup;

    if (__atomic_test_and_set(
            &g_edge_virtgpu_cleanup_guard, __ATOMIC_ACQUIRE))
        return;
    for (;;) {
        edge_virtgpu_lock_raw();
        if (!g_edge_virtgpu_cleanup_count) {
            edge_virtgpu_unlock_raw();
            break;
        }
        cleanup = g_edge_virtgpu_cleanup[g_edge_virtgpu_cleanup_head];
        memset(&g_edge_virtgpu_cleanup[g_edge_virtgpu_cleanup_head], 0,
               sizeof(g_edge_virtgpu_cleanup[0]));
        g_edge_virtgpu_cleanup_head =
            (g_edge_virtgpu_cleanup_head + 1u) %
            EDGE_VIRTGPU_CLEANUP_COUNT;
        g_edge_virtgpu_cleanup_count--;
        edge_virtgpu_unlock_raw();

        if ((cleanup.kind == EDGE_VIRTGPU_CLEANUP_RESOURCE_DESTROY ||
             cleanup.kind == EDGE_VIRTGPU_CLEANUP_RESOURCE_DETACH) &&
            cleanup.resource_operation)
            (void)cleanup.resource_operation(
                cleanup.backend_context, cleanup.context_id,
                cleanup.resource_id);
        else if (cleanup.kind == EDGE_VIRTGPU_CLEANUP_CONTEXT_DESTROY &&
                 cleanup.context_operation)
            (void)cleanup.context_operation(
                cleanup.backend_context, cleanup.context_id);
        edge_virtgpu_backing_release(&cleanup.backing);
    }
    __atomic_clear(&g_edge_virtgpu_cleanup_guard, __ATOMIC_RELEASE);
    if (__atomic_load_n(
            &g_edge_virtgpu_cleanup_count, __ATOMIC_ACQUIRE))
        edge_virtgpu_cleanup_drain();
}

static void *edge_virtgpu_temporary_storage_allocate(
    uint64_t size, uint32_t *page_count)
{
    uint64_t pages;

    if (!page_count || !size ||
        size > UINT32_MAX - (EDGE_VIRTGPU_PAGE_SIZE - 1u))
        return 0;
    pages = (size + EDGE_VIRTGPU_PAGE_SIZE - 1u) /
        EDGE_VIRTGPU_PAGE_SIZE;
    if (!pages || pages > UINT32_MAX) return 0;
    *page_count = (uint32_t)pages;
    return arch_vm_alloc_pages(pages);
}

static edge_virtgpu_submission_t *
edge_virtgpu_submission_allocate_locked(uint32_t context_id)
{
    for (uint32_t index = 0; index < EDGE_VIRTGPU_SUBMISSION_COUNT;
         ++index) {
        edge_virtgpu_submission_t *submission =
            &g_edge_virtgpu_submissions[index];

        if (submission->used) continue;
        memset(submission, 0, sizeof(*submission));
        submission->used = 1u;
        submission->context_id = context_id;
        submission->completion_id = g_edge_virtgpu_next_completion_id++;
        if (!submission->completion_id)
            submission->completion_id = g_edge_virtgpu_next_completion_id++;
        return submission;
    }
    return NULL;
}

static edge_virtgpu_submission_t *
edge_virtgpu_submission_locked(uint64_t completion_id)
{
    for (uint32_t index = 0; index < EDGE_VIRTGPU_SUBMISSION_COUNT;
         ++index)
        if (g_edge_virtgpu_submissions[index].used &&
            g_edge_virtgpu_submissions[index].completion_id == completion_id)
            return &g_edge_virtgpu_submissions[index];
    return NULL;
}

static void edge_virtgpu_resource_maybe_release(
    edge_virtgpu_resource_t *resource);
static void edge_virtgpu_dispatch_ready_present(void);
static void edge_virtgpu_sync_files_notify_ready(void);
static void edge_virtgpu_resource_wait_release(uint32_t object_id);
static volatile uint32_t g_edge_virtgpu_present_diagnostic_count;

static int edge_virtgpu_present_diagnostic_enabled(void)
{
    return __atomic_fetch_add(
               &g_edge_virtgpu_present_diagnostic_count, 1u,
               __ATOMIC_RELAXED) < 96u;
}

static void edge_virtgpu_submission_release_references_locked(
    edge_virtgpu_submission_t *submission, int signal)
{
    if (!submission || !submission->used) return;
    for (uint32_t index = 0; index < submission->output_count; ++index) {
        uint32_t object_id = submission->outputs[index].handle;

        if (signal)
            (void)edge_virtgpu_syncobj_signal_object_locked(
                object_id, submission->outputs[index].point);
        edge_virtgpu_syncobj_release_object_locked(object_id);
    }
    if (submission->output_fence_object_id) {
        if (signal)
            (void)edge_virtgpu_syncobj_signal_object_locked(
                submission->output_fence_object_id, 1u);
        edge_virtgpu_syncobj_release_object_locked(
            submission->output_fence_object_id);
    }
    for (uint32_t index = 0; index < submission->resource_count; ++index) {
        edge_virtgpu_resource_t *resource = edge_virtgpu_prime_resource(
            (int32_t)submission->resource_object_ids[index]);

        if (!resource || !resource->submission_refs) continue;
        resource->submission_refs--;
        edge_virtgpu_resource_maybe_release(resource);
    }
    if (submission->resource_count) {
        (void)__atomic_add_fetch(
            &g_edge_virtgpu_sync_sequence, 1u, __ATOMIC_RELEASE);
        kernel_runtime_notify_sequence(&g_edge_virtgpu_sync_sequence);
    }
}

static void edge_virtgpu_submission_finish(
    uint64_t completion_id, int signal)
{
    edge_virtgpu_submission_t completed;
    edge_virtgpu_client_t *client = NULL;

    memset(&completed, 0, sizeof(completed));
    edge_virtgpu_lock();
    {
        edge_virtgpu_submission_t *submission =
            edge_virtgpu_submission_locked(completion_id);

        if (submission) {
            uint32_t context_id = submission->context_id;

            edge_virtgpu_submission_release_references_locked(
                submission, signal);
            completed = *submission;
            memset(submission, 0, sizeof(*submission));
            for (uint32_t index = 0;
                 index < EDGE_VIRTGPU_CLIENT_COUNT; ++index)
                if (g_edge_virtgpu_clients[index].used &&
                    g_edge_virtgpu_clients[index].context_id == context_id) {
                    client = &g_edge_virtgpu_clients[index];
                    break;
                }
            edge_virtgpu_client_maybe_release(client);
        }
    }
    edge_virtgpu_unlock();
    edge_virtgpu_storage_release(
        completed.commands, completed.command_pages);
    edge_virtgpu_storage_release(
        completed.syncobj_storage, completed.syncobj_pages);
    edge_virtgpu_dispatch_ready_present();
    edge_virtgpu_sync_files_notify_ready();
}

void edge_virtgpu_backend_submission_complete(
    uint64_t completion_id, int status)
{
    (void)status;
    edge_virtgpu_submission_finish(completion_id, 1);
}

static void edge_virtgpu_resource_release(
    edge_virtgpu_resource_t *resource) {
    edge_virtgpu_cleanup_t cleanup;
    edge_virtgpu_client_t *client = 0;
    uint32_t context_id;

    if (!resource || !resource->used || resource->backing_object_id)
        return;
    context_id = resource->context_id;
    for (uint32_t index = 0; index < EDGE_VIRTGPU_CLIENT_COUNT; ++index)
        if (g_edge_virtgpu_clients[index].used &&
            g_edge_virtgpu_clients[index].context_id == context_id) {
            client = &g_edge_virtgpu_clients[index];
            break;
        }
    memset(&cleanup, 0, sizeof(cleanup));
    cleanup.kind = EDGE_VIRTGPU_CLEANUP_RESOURCE_DESTROY;
    cleanup.backend_context = g_edge_virtgpu_backend.context;
    cleanup.resource_operation =
        g_edge_virtgpu_backend.operations.resource_destroy;
    cleanup.context_id = context_id;
    cleanup.resource_id = resource->resource_id;
    cleanup.backing = resource->backing;
    if (edge_virtgpu_cleanup_enqueue_locked(&cleanup) < 0)
        return;
    memset(resource, 0, sizeof(*resource));
    edge_virtgpu_client_maybe_release(client);
}

static void edge_virtgpu_resource_maybe_release(
    edge_virtgpu_resource_t *resource) {
    edge_virtgpu_cleanup_t cleanup;
    edge_virtgpu_resource_t *backing;

    if (!resource || !resource->used || resource->backend_creating ||
        resource->handle_open ||
        resource->framebuffer_refs || resource->submission_refs ||
        resource->wait_refs || resource->present_refs)
        return;
    if (resource->backing_object_id) {
        backing = edge_virtgpu_prime_resource(
            resource->backing_object_id);
        if (backing && resource->context_id &&
            g_edge_virtgpu_backend.operations.resource_detach) {
            memset(&cleanup, 0, sizeof(cleanup));
            cleanup.kind = EDGE_VIRTGPU_CLEANUP_RESOURCE_DETACH;
            cleanup.backend_context = g_edge_virtgpu_backend.context;
            cleanup.resource_operation =
                g_edge_virtgpu_backend.operations.resource_detach;
            cleanup.context_id = resource->context_id;
            cleanup.resource_id = backing->resource_id;
            if (edge_virtgpu_cleanup_enqueue_locked(&cleanup) < 0)
                return;
        }
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
    version.version_minor = 1;
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
        case EDGE_DRM_CAP_DUMB_BUFFER:
        case EDGE_DRM_CAP_VBLANK_HIGH_CRTC:
        case EDGE_DRM_CAP_TIMESTAMP_MONOTONIC:
        case EDGE_DRM_CAP_CRTC_IN_VBLANK_EVENT:
            capability.value = 1u;
            break;
        case EDGE_DRM_CAP_DUMB_PREFERRED_DEPTH:
        case EDGE_DRM_CAP_DUMB_PREFER_SHADOW:
        case EDGE_DRM_CAP_ASYNC_PAGE_FLIP:
        case EDGE_DRM_CAP_ADDFB2_MODIFIERS:
        case EDGE_DRM_CAP_PAGE_FLIP_TARGET:
            capability.value = 0u;
            break;
        case EDGE_DRM_CAP_PRIME:
            capability.value = edge_virtgpu_framebuffer_available() ?
                EDGE_DRM_PRIME_CAP_IMPORT |
                    EDGE_DRM_PRIME_CAP_EXPORT : 0u;
            break;
        case EDGE_DRM_CAP_CURSOR_WIDTH:
        case EDGE_DRM_CAP_CURSOR_HEIGHT:
            capability.value = 64u;
            break;
        case EDGE_DRM_CAP_SYNCOBJ:
        case EDGE_DRM_CAP_SYNCOBJ_TIMELINE:
            capability.value = 1u;
            break;
        default:
            return -EDGE_LINUX_EINVAL;
    }
    return edge_virtgpu_copy_to(
               request, request->argument, &capability,
               sizeof(capability)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int edge_virtgpu_syncobj_copy_handles(
    const kernel_ioctl_request_t *request, uint64_t address,
    uint32_t count, uint32_t *handles)
{
    if (!count || count > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT ||
        !address || !handles)
        return -EDGE_LINUX_EINVAL;
    return edge_virtgpu_copy_from(
               request, handles, address,
               (uint64_t)count * sizeof(handles[0])) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int edge_virtgpu_syncobj_copy_points(
    const kernel_ioctl_request_t *request, uint64_t address,
    uint32_t count, uint64_t *points)
{
    if (!count || count > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT ||
        !address || !points)
        return -EDGE_LINUX_EINVAL;
    return edge_virtgpu_copy_from(
               request, points, address,
               (uint64_t)count * sizeof(points[0])) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_syncobj_create_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_create_t command;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags & ~EDGE_DRM_SYNCOBJ_CREATE_SIGNALED)
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    result = edge_virtgpu_syncobj_create_locked(
        identity, command.flags & EDGE_DRM_SYNCOBJ_CREATE_SIGNALED,
        &command.handle);
    edge_virtgpu_unlock();
    if (result < 0) return result;
    return edge_virtgpu_copy_to(
               request, request->argument, &command, sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_syncobj_destroy_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_destroy_t command;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad) return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    result = edge_virtgpu_syncobj_remove_handle_locked(
        identity, command.handle);
    edge_virtgpu_unlock();
    return result;
}

static int64_t edge_virtgpu_syncobj_array_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request, int signal)
{
    edge_virtgpu_syncobj_array_t command;
    uint32_t handles[EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT];
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad) return -EDGE_LINUX_EINVAL;
    result = edge_virtgpu_syncobj_copy_handles(
        request, command.handles, command.count_handles, handles);
    if (result < 0) return result;
    edge_virtgpu_lock();
    for (uint32_t index = 0; index < command.count_handles; ++index) {
        result = signal ?
            edge_virtgpu_syncobj_signal_locked(
                identity, handles[index], 0u) :
            edge_virtgpu_syncobj_reset_locked(identity, handles[index]);
        if (result < 0) break;
    }
    edge_virtgpu_unlock();
    return result;
}

static int64_t edge_virtgpu_syncobj_timeline_signal_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_timeline_array_t command;
    uint8_t *storage;
    uint32_t *handles;
    uint64_t *points;
    uint64_t points_offset;
    uint32_t pages;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags) return -EDGE_LINUX_EINVAL;
    if (!command.count_handles ||
        command.count_handles > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT)
        return -EDGE_LINUX_EINVAL;
    points_offset = edge_virtgpu_align_up(
        (uint64_t)command.count_handles * sizeof(handles[0]),
        _Alignof(uint64_t));
    storage = edge_virtgpu_temporary_storage_allocate(
        points_offset + (uint64_t)command.count_handles *
            sizeof(points[0]),
        &pages);
    if (!storage) return -EDGE_LINUX_ENOMEM;
    handles = (uint32_t *)storage;
    points = (uint64_t *)(storage + points_offset);
    result = edge_virtgpu_syncobj_copy_handles(
        request, command.handles, command.count_handles, handles);
    if (result == 0)
        result = edge_virtgpu_syncobj_copy_points(
            request, command.points, command.count_handles, points);
    if (result == 0) {
        edge_virtgpu_lock();
        for (uint32_t index = 0;
             index < command.count_handles; ++index) {
            result = edge_virtgpu_syncobj_signal_locked(
                identity, handles[index], points[index]);
            if (result < 0) break;
        }
        edge_virtgpu_unlock();
    }
    edge_virtgpu_storage_release(storage, pages);
    return result;
}

static int edge_virtgpu_syncobj_wait_ready_locked(
    uint64_t identity, const uint32_t *handles, const uint64_t *points,
    uint32_t count, uint32_t flags, uint32_t *first)
{
    int wait_all = (flags & EDGE_DRM_SYNCOBJ_WAIT_ALL) != 0;
    int available = (flags & EDGE_DRM_SYNCOBJ_WAIT_AVAILABLE) != 0;
    uint32_t ready_count = 0u;

    for (uint32_t index = 0; index < count; ++index) {
        int ready = edge_virtgpu_syncobj_point_ready_locked(
            identity, handles[index], points ? points[index] : 0u,
            available);

        if (ready < 0) return ready;
        if (ready) {
            if (!ready_count && first) *first = index;
            ready_count++;
        } else if (wait_all) {
            return 0;
        }
    }
    return wait_all ? ready_count == count : ready_count != 0u;
}

static int64_t edge_virtgpu_syncobj_wait_common(
    uint64_t identity, const kernel_ioctl_request_t *request,
    uint64_t handles_address, uint64_t points_address,
    uint32_t count, uint32_t flags, int64_t timeout_ns,
    uint32_t *first_signaled)
{
    uint8_t *storage;
    uint32_t *handles;
    uint64_t *points = 0;
    uint64_t points_offset;
    uint32_t pages;
    uint64_t deadline_us;
    uint64_t observed_sequence;
    int result;

    if (flags & ~EDGE_DRM_SYNCOBJ_WAIT_FLAGS)
        return -EDGE_LINUX_EINVAL;
    if (!count || count > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT)
        return -EDGE_LINUX_EINVAL;
    points_offset = edge_virtgpu_align_up(
        (uint64_t)count * sizeof(handles[0]), _Alignof(uint64_t));
    storage = edge_virtgpu_temporary_storage_allocate(
        points_offset + (points_address ?
            (uint64_t)count * sizeof(uint64_t) : 0u),
        &pages);
    if (!storage) return -EDGE_LINUX_ENOMEM;
    handles = (uint32_t *)storage;
    if (points_address)
        points = (uint64_t *)(storage + points_offset);
    result = edge_virtgpu_syncobj_copy_handles(
        request, handles_address, count, handles);
    if (result < 0) goto out;
    if (points_address) {
        result = edge_virtgpu_syncobj_copy_points(
            request, points_address, count, points);
        if (result < 0) goto out;
    }
    deadline_us = timeout_ns < 0 ? UINT64_MAX :
        ((uint64_t)timeout_ns + 999u) / 1000u;
    for (;;) {
        edge_virtgpu_lock();
        observed_sequence = __atomic_load_n(
            &g_edge_virtgpu_sync_sequence, __ATOMIC_ACQUIRE);
        result = edge_virtgpu_syncobj_wait_ready_locked(
            identity, handles, points,
            count, flags, first_signaled);
        edge_virtgpu_unlock();
        if (result < 0) goto out;
        if (result) {
            result = 0;
            goto out;
        }
        if (!timeout_ns ||
            (deadline_us != UINT64_MAX &&
             boottime_monotonic_us() >= deadline_us)) {
            result = -EDGE_LINUX_ETIME;
            goto out;
        }
        result = kernel_runtime_wait_sequence(
            &g_edge_virtgpu_sync_sequence,
            observed_sequence, deadline_us);
        if (result < 0) {
            result = -EDGE_LINUX_EINTR;
            goto out;
        }
    }
out:
    edge_virtgpu_storage_release(storage, pages);
    return result;
}

static int64_t edge_virtgpu_syncobj_wait_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_wait_t command;
    int64_t result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad) return -EDGE_LINUX_EINVAL;
    result = edge_virtgpu_syncobj_wait_common(
        identity, request, command.handles, 0u,
        command.count_handles, command.flags, command.timeout_ns,
        &command.first_signaled);
    if (result < 0) return result;
    return edge_virtgpu_copy_to(
               request, request->argument, &command, sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_syncobj_timeline_wait_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_timeline_wait_t command;
    int64_t result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad) return -EDGE_LINUX_EINVAL;
    result = edge_virtgpu_syncobj_wait_common(
        identity, request, command.handles, command.points,
        command.count_handles, command.flags, command.timeout_ns,
        &command.first_signaled);
    if (result < 0) return result;
    return edge_virtgpu_copy_to(
               request, request->argument, &command, sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_syncobj_query_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_timeline_array_t command;
    uint8_t *storage;
    uint32_t *handles;
    uint64_t *points;
    uint64_t points_offset;
    uint32_t pages;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags & ~EDGE_DRM_SYNCOBJ_QUERY_LAST_SUBMITTED)
        return -EDGE_LINUX_EINVAL;
    if (!command.count_handles ||
        command.count_handles > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT ||
        !command.points)
        return -EDGE_LINUX_EINVAL;
    points_offset = edge_virtgpu_align_up(
        (uint64_t)command.count_handles * sizeof(handles[0]),
        _Alignof(uint64_t));
    storage = edge_virtgpu_temporary_storage_allocate(
        points_offset + (uint64_t)command.count_handles *
            sizeof(points[0]),
        &pages);
    if (!storage) return -EDGE_LINUX_ENOMEM;
    handles = (uint32_t *)storage;
    points = (uint64_t *)(storage + points_offset);
    result = edge_virtgpu_syncobj_copy_handles(
        request, command.handles, command.count_handles, handles);
    if (result == 0) {
        edge_virtgpu_lock();
        for (uint32_t index = 0;
             index < command.count_handles; ++index) {
            edge_virtgpu_syncobj_t *object =
                edge_virtgpu_syncobj_locked(identity, handles[index]);

            if (!object) {
                result = -EDGE_LINUX_EINVAL;
                break;
            }
            points[index] =
                (command.flags & EDGE_DRM_SYNCOBJ_QUERY_LAST_SUBMITTED) ?
                    object->available_point : object->point;
            result = 0;
        }
        edge_virtgpu_unlock();
    }
    if (result == 0 && edge_virtgpu_copy_to(
            request, command.points, points,
            (uint64_t)command.count_handles * sizeof(points[0])) < 0)
        result = -EDGE_LINUX_EFAULT;
    edge_virtgpu_storage_release(storage, pages);
    return result;
}

static int edge_virtgpu_syncobj_transfer_objects_locked(
    uint32_t source_object_id, uint64_t source_point,
    uint32_t destination_object_id, uint64_t destination_point)
{
    edge_virtgpu_syncobj_t *source =
        edge_virtgpu_syncobj_object_locked(source_object_id);
    edge_virtgpu_syncobj_t *destination =
        edge_virtgpu_syncobj_object_locked(destination_object_id);
    uint64_t published_point = destination_point ? destination_point : 1u;

    if (!source || !destination) return -EDGE_LINUX_EINVAL;
    if ((source_point && source->available_point < source_point) ||
        (!source_point && !source->available_point))
        return -EDGE_LINUX_EINVAL;
    if ((source_point && source->point >= source_point) ||
        (!source_point && source->signaled)) {
        if (published_point > destination->available_point)
            destination->available_point = published_point;
        if (published_point > destination->point)
            destination->point = published_point;
        destination->signaled = 1u;
        edge_virtgpu_syncobj_notify_locked(destination_object_id);
        return 0;
    }
    if (source->references == UINT16_MAX ||
        destination->references == UINT16_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNCOBJ_TRANSFER_COUNT; ++index) {
        edge_virtgpu_syncobj_transfer_record_t *transfer =
            &g_edge_virtgpu_syncobj_transfers[index];

        if (transfer->used) continue;
        memset(transfer, 0, sizeof(*transfer));
        transfer->used = 1u;
        transfer->source_object_id = source_object_id;
        transfer->destination_object_id = destination_object_id;
        transfer->source_point = source_point;
        transfer->destination_point = destination_point;
        source->references++;
        destination->references++;
        if (published_point > destination->available_point)
            destination->available_point = published_point;
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int64_t edge_virtgpu_syncobj_transfer_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_transfer_t command;
    edge_virtgpu_syncobj_handle_record_t *source;
    edge_virtgpu_syncobj_handle_record_t *destination;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags || command.pad) return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    source = edge_virtgpu_syncobj_handle_locked(
        identity, command.source_handle);
    destination = edge_virtgpu_syncobj_handle_locked(
        identity, command.destination_handle);
    if (!source || !destination) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        result = edge_virtgpu_syncobj_transfer_objects_locked(
            source->object_id, command.source_point,
            destination->object_id, command.destination_point);
    }
    edge_virtgpu_unlock();
    return result;
}

static int edge_virtgpu_sync_file_allocate_locked(
    uint32_t object_id, uint64_t point, int sync_file)
{
    edge_virtgpu_syncobj_t *object =
        edge_virtgpu_syncobj_object_locked(object_id);

    if (!object || object->references == UINT16_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNC_FILE_COUNT; ++index) {
        edge_virtgpu_sync_file_t *file =
            &g_edge_virtgpu_sync_files[index];

        if (file->used) continue;
        memset(file, 0, sizeof(*file));
        file->used = 1u;
        file->sync_file = sync_file ? 1u : 0u;
        file->references = 1u;
        file->object_id = object_id;
        file->point = point;
        file->leaf_count = 1u;
        memcpy(file->name, "edgeos-virtgpu", sizeof("edgeos-virtgpu"));
        object->references++;
        return (int)(index + 1u);
    }
    return -EDGE_LINUX_ENOSPC;
}

static edge_virtgpu_sync_file_t *edge_virtgpu_sync_file_locked(
    int32_t file_id)
{
    if (file_id <= 0 ||
        file_id > (int32_t)EDGE_VIRTGPU_SYNC_FILE_COUNT)
        return NULL;
    if (!g_edge_virtgpu_sync_files[(uint32_t)file_id - 1u].used)
        return NULL;
    return &g_edge_virtgpu_sync_files[(uint32_t)file_id - 1u];
}

static int edge_virtgpu_sync_file_retain_locked(int32_t file_id)
{
    edge_virtgpu_sync_file_t *file =
        edge_virtgpu_sync_file_locked(file_id);

    if (!file) return -EDGE_LINUX_EBADF;
    if (file->references == UINT16_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    file->references++;
    return 0;
}

static int edge_virtgpu_sync_file_status_locked(
    int32_t file_id, uint64_t *timestamp_ns)
{
    uint32_t depth = 0u;
    int status = 1;
    uint64_t latest = 0u;

    g_edge_virtgpu_sync_walk[depth++] = file_id;
    while (depth) {
        edge_virtgpu_sync_file_t *file =
            edge_virtgpu_sync_file_locked(
                g_edge_virtgpu_sync_walk[--depth]);

        if (!file || !file->sync_file) return -EDGE_LINUX_EINVAL;
        if (file->components[0] > 0 || file->components[1] > 0) {
            if (depth + 2u > EDGE_VIRTGPU_SYNC_FILE_COUNT)
                return -EDGE_LINUX_EOVERFLOW;
            g_edge_virtgpu_sync_walk[depth++] = file->components[1];
            g_edge_virtgpu_sync_walk[depth++] = file->components[0];
            continue;
        }
        {
            edge_virtgpu_syncobj_t *object =
                edge_virtgpu_syncobj_object_locked(file->object_id);
            int ready;

            if (!object) return -EDGE_LINUX_EINVAL;
            ready = edge_virtgpu_syncobj_object_ready_locked(
                file->object_id, file->point, 0);
            if (ready < 0) return ready;
            if (!ready) status = 0;
            if (ready && !object->signal_timestamp_ns)
                object->signal_timestamp_ns =
                    boottime_monotonic_us() * 1000u;
            if (object->signal_timestamp_ns > latest)
                latest = object->signal_timestamp_ns;
        }
    }
    if (timestamp_ns) *timestamp_ns = status > 0 ? latest : 0u;
    return status;
}

static int edge_virtgpu_sync_file_leaf_info_locked(
    int32_t file_id, uint32_t wanted, edge_sync_fence_info_t *info)
{
    uint32_t depth = 0u;
    uint32_t current = 0u;

    if (!info) return -EDGE_LINUX_EINVAL;
    g_edge_virtgpu_sync_walk[depth++] = file_id;
    while (depth) {
        edge_virtgpu_sync_file_t *file =
            edge_virtgpu_sync_file_locked(
                g_edge_virtgpu_sync_walk[--depth]);

        if (!file || !file->sync_file) return -EDGE_LINUX_EINVAL;
        if (file->components[0] > 0 || file->components[1] > 0) {
            if (depth + 2u > EDGE_VIRTGPU_SYNC_FILE_COUNT)
                return -EDGE_LINUX_EOVERFLOW;
            g_edge_virtgpu_sync_walk[depth++] = file->components[1];
            g_edge_virtgpu_sync_walk[depth++] = file->components[0];
            continue;
        }
        if (current++ != wanted) continue;
        {
            edge_virtgpu_syncobj_t *object =
                edge_virtgpu_syncobj_object_locked(file->object_id);
            int status;

            if (!object) return -EDGE_LINUX_EINVAL;
            status = edge_virtgpu_syncobj_object_ready_locked(
                file->object_id, file->point, 0);
            if (status < 0) return status;
            if (status && !object->signal_timestamp_ns)
                object->signal_timestamp_ns =
                    boottime_monotonic_us() * 1000u;
            memset(info, 0, sizeof(*info));
            memcpy(info->obj_name, "virtio-gpu", sizeof("virtio-gpu"));
            memcpy(info->driver_name, "virtio_gpu", sizeof("virtio_gpu"));
            info->status = status;
            info->timestamp_ns = status ?
                object->signal_timestamp_ns : 0u;
            return 0;
        }
    }
    return -EDGE_LINUX_EINVAL;
}

static int edge_virtgpu_sync_file_merge_locked(
    int32_t first_id, int32_t second_id, const char name[32])
{
    edge_virtgpu_sync_file_t *first =
        edge_virtgpu_sync_file_locked(first_id);
    edge_virtgpu_sync_file_t *second =
        edge_virtgpu_sync_file_locked(second_id);

    if (!first || !second || !first->sync_file || !second->sync_file)
        return -EDGE_LINUX_ENOENT;
    if (first->leaf_count > UINT32_MAX - second->leaf_count)
        return -EDGE_LINUX_EOVERFLOW;
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNC_FILE_COUNT; ++index) {
        edge_virtgpu_sync_file_t *merged =
            &g_edge_virtgpu_sync_files[index];
        int result;

        if (merged->used) continue;
        result = edge_virtgpu_sync_file_retain_locked(first_id);
        if (result < 0) return result;
        result = edge_virtgpu_sync_file_retain_locked(second_id);
        if (result < 0) {
            first->references--;
            return result;
        }
        memset(merged, 0, sizeof(*merged));
        merged->used = 1u;
        merged->sync_file = 1u;
        merged->references = 1u;
        merged->leaf_count = first->leaf_count + second->leaf_count;
        merged->components[0] = first_id;
        merged->components[1] = second_id;
        memcpy(merged->name, name, sizeof(merged->name));
        merged->name[sizeof(merged->name) - 1u] = 0;
        return (int)(index + 1u);
    }
    return -EDGE_LINUX_ENOSPC;
}

static void edge_virtgpu_sync_file_release_locked(int32_t file_id)
{
    edge_virtgpu_sync_file_t *file;
    uint32_t object_id;
    int32_t first_component;
    int32_t second_component;

    if (file_id <= 0 || file_id > (int32_t)EDGE_VIRTGPU_SYNC_FILE_COUNT)
        return;
    file = &g_edge_virtgpu_sync_files[(uint32_t)file_id - 1u];
    if (!file->used || !file->references) return;
    file->references--;
    if (file->references) return;
    object_id = file->object_id;
    first_component = file->components[0];
    second_component = file->components[1];
    memset(file, 0, sizeof(*file));
    if (first_component > 0 || second_component > 0) {
        edge_virtgpu_sync_file_release_locked(first_component);
        edge_virtgpu_sync_file_release_locked(second_component);
    } else {
        edge_virtgpu_syncobj_release_object_locked(object_id);
    }
}

static int64_t edge_virtgpu_syncobj_handle_to_fd_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_handle_t command;
    edge_virtgpu_syncobj_handle_record_t *handle;
    int file_id;
    int descriptor;

    if (!request->argument || edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad ||
        (command.flags & ~(EDGE_DRM_SYNCOBJ_HANDLE_EXPORT_SYNC_FILE |
                           EDGE_DRM_SYNCOBJ_HANDLE_TIMELINE)))
        return -EDGE_LINUX_EINVAL;
    if (!(command.flags & EDGE_DRM_SYNCOBJ_HANDLE_TIMELINE) &&
        command.point)
        return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    handle = edge_virtgpu_syncobj_handle_locked(identity, command.handle);
    file_id = handle ? edge_virtgpu_sync_file_allocate_locked(
        handle->object_id,
        (command.flags & EDGE_DRM_SYNCOBJ_HANDLE_TIMELINE) ?
            command.point : 0u,
        command.flags & EDGE_DRM_SYNCOBJ_HANDLE_EXPORT_SYNC_FILE) :
        -EDGE_LINUX_EINVAL;
    edge_virtgpu_unlock();
    if (file_id < 0) return file_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_DRM_SYNC, file_id,
        EDGE_VIRTGPU_PRIME_RDWR, EDGE_VIRTGPU_PRIME_CLOEXEC);
    if (descriptor < 0) {
        edge_virtgpu_sync_file_release(file_id);
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

static int64_t edge_virtgpu_syncobj_fd_to_handle_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_handle_t command;
    edge_virtgpu_sync_file_t *file;
    int file_id;
    int result;

    if (!request->argument || edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad ||
        (command.flags & ~(EDGE_DRM_SYNCOBJ_HANDLE_IMPORT_SYNC_FILE |
                           EDGE_DRM_SYNCOBJ_HANDLE_TIMELINE)))
        return -EDGE_LINUX_EINVAL;
    if (!(command.flags & EDGE_DRM_SYNCOBJ_HANDLE_TIMELINE) &&
        command.point)
        return -EDGE_LINUX_EINVAL;
    file_id = kernel_anonymous_fd_descriptor_object_id(
        command.fd, KERNEL_ANONYMOUS_FD_DRM_SYNC);
    if (file_id < 0) return file_id;
    edge_virtgpu_lock();
    file = file_id > 0 &&
        file_id <= (int32_t)EDGE_VIRTGPU_SYNC_FILE_COUNT ?
        &g_edge_virtgpu_sync_files[(uint32_t)file_id - 1u] : 0;
    if (!file || !file->used ||
        (!!(command.flags & EDGE_DRM_SYNCOBJ_HANDLE_IMPORT_SYNC_FILE) !=
         !!file->sync_file)) {
        result = -EDGE_LINUX_EINVAL;
    } else if (command.flags & EDGE_DRM_SYNCOBJ_HANDLE_IMPORT_SYNC_FILE) {
        edge_virtgpu_syncobj_handle_record_t *destination =
            edge_virtgpu_syncobj_handle_locked(identity, command.handle);

        result = destination ?
            edge_virtgpu_syncobj_transfer_objects_locked(
                file->object_id, file->point,
                destination->object_id,
                (command.flags & EDGE_DRM_SYNCOBJ_HANDLE_TIMELINE) ?
                    command.point : 0u) :
            -EDGE_LINUX_EINVAL;
    } else {
        result = edge_virtgpu_syncobj_add_handle_locked(
            identity, file->object_id, &command.handle);
    }
    edge_virtgpu_unlock();
    if (result < 0) return result;
    return edge_virtgpu_copy_to(
               request, request->argument, &command, sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_virtgpu_syncobj_eventfd_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    edge_virtgpu_syncobj_eventfd_t command;
    edge_virtgpu_syncobj_handle_record_t *handle;
    int event_id;
    int result = -EDGE_LINUX_ENOSPC;

    if (!request->argument || edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad ||
        (command.flags & ~EDGE_DRM_SYNCOBJ_WAIT_AVAILABLE))
        return -EDGE_LINUX_EINVAL;
    event_id = command.fd < 0 ? -1 :
        kernel_anonymous_fd_descriptor_object_id(
            command.fd, KERNEL_ANONYMOUS_FD_EVENT);
    if (command.fd >= 0 && event_id < 0) return event_id;
    if (event_id >= 0 && kernel_eventfd_retain(event_id) < 0)
        return -EDGE_LINUX_EBADF;
    edge_virtgpu_lock();
    handle = edge_virtgpu_syncobj_handle_locked(identity, command.handle);
    if (!handle) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        int32_t available_slot = -1;

        for (uint32_t index = 0;
             index < EDGE_VIRTGPU_SYNCOBJ_EVENT_COUNT; ++index) {
            edge_virtgpu_syncobj_event_t *event =
                &g_edge_virtgpu_syncobj_events[index];

            if (!event->used && available_slot < 0)
                available_slot = (int32_t)index;
            if (event->used && event->owner == identity &&
                event->owner_handle == command.handle &&
                event->point == command.point) {
                kernel_eventfd_release(event->event_id);
                memset(event, 0, sizeof(*event));
                available_slot = (int32_t)index;
            }
        }
        if (event_id < 0) {
            result = 0;
        } else if (available_slot >= 0) {
            edge_virtgpu_syncobj_event_t *event =
                &g_edge_virtgpu_syncobj_events[(uint32_t)available_slot];

            event->used = 1u;
            event->available = !!(
                command.flags & EDGE_DRM_SYNCOBJ_WAIT_AVAILABLE);
            event->object_id = handle->object_id;
            event->point = command.point;
            event->event_id = event_id;
            event->owner_handle = command.handle;
            event->owner = identity;
            result = 0;
            if (edge_virtgpu_syncobj_object_ready_locked(
                    handle->object_id, command.point,
                    event->available) > 0)
                edge_virtgpu_syncobj_notify_locked(handle->object_id);
        }
    }
    edge_virtgpu_unlock();
    if (event_id >= 0 && result < 0) kernel_eventfd_release(event_id);
    return result;
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
            value = 0u;
            break;
        case EDGE_VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME:
            value = 1u;
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
    void *backend_context;
    int (*resource_create)(
        void *, uint32_t, uint32_t,
        const edge_virtgpu_resource_create_t *,
        const edge_virtgpu_backing_t *, uint64_t);
    edge_virtgpu_backing_t backing;
    uint64_t allocation_size;
    uint64_t resource_size;
    uint32_t context_id;
    uint32_t resource_id;
    uint32_t page_count;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    resource_size = command.size ? command.size : EDGE_VIRTGPU_PAGE_SIZE;
    if (resource_size > EDGE_VIRTGPU_MAX_RESOURCE_SIZE)
        return -EDGE_LINUX_EINVAL;
    page_count =
        (resource_size + EDGE_VIRTGPU_PAGE_SIZE - 1u) /
        EDGE_VIRTGPU_PAGE_SIZE;
    allocation_size = (uint64_t)page_count * EDGE_VIRTGPU_PAGE_SIZE;
    if (edge_virtgpu_backing_allocate(page_count, &backing) < 0)
        return -EDGE_LINUX_ENOMEM;

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
    resource->backend_creating = 1u;
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
    resource->backing = backing;
    resource->map_offset = g_edge_virtgpu_next_map;
    g_edge_virtgpu_next_map = edge_virtgpu_align_up(
        g_edge_virtgpu_next_map + allocation_size,
        EDGE_VIRTGPU_PAGE_SIZE);
    resource_create =
        g_edge_virtgpu_backend.operations.resource_create;
    backend_context = g_edge_virtgpu_backend.context;
    context_id = resource->context_id;
    resource_id = resource->resource_id;
    if (!resource_create) {
        memset(resource, 0, sizeof(*resource));
        result = -EDGE_LINUX_EIO;
        goto fail;
    }

    edge_virtgpu_unlock();
    result = resource_create(
        backend_context, context_id, resource_id,
        &create, &backing, allocation_size);
    edge_virtgpu_lock();
    if (result < 0 || !resource->used ||
        resource->owner != identity ||
        resource->context_id != context_id ||
        resource->resource_id != resource_id ||
        !resource->backend_creating) {
        if (resource->used && resource->owner == identity &&
            resource->context_id == context_id &&
            resource->resource_id == resource_id)
            memset(resource, 0, sizeof(*resource));
        result = -EDGE_LINUX_EIO;
        goto fail;
    }
    resource->backend_creating = 0u;
    resource->backend_ready = 1u;
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
    edge_virtgpu_backing_release(&backing);
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
    void *backend_context;
    int (*transfer_operation)(
        void *, uint32_t, uint32_t,
        const edge_virtgpu_transfer_t *);
    uint32_t object_id;
    uint32_t context_id;
    uint32_t resource_id;
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
    if (resource->wait_refs == UINT32_MAX) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_EOVERFLOW;
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
    object_id = (uint32_t)edge_virtgpu_prime_object_id(resource);
    context_id = resource->context_id;
    resource_id = resource->resource_id;
    backend_context = g_edge_virtgpu_backend.context;
    transfer_operation = to_host ?
        g_edge_virtgpu_backend.operations.transfer_to_host :
        g_edge_virtgpu_backend.operations.transfer_from_host;
    resource->wait_refs++;
    edge_virtgpu_unlock();

    result = transfer_operation ? transfer_operation(
        backend_context, context_id, resource_id, &transfer) : -1;
    edge_virtgpu_resource_wait_release(object_id);
    return result < 0 ? -EDGE_LINUX_EIO : 0;
}

static int edge_virtgpu_execbuffer_copy_syncobjs(
    const kernel_ioctl_request_t *request, uint64_t address,
    uint32_t count, uint32_t stride,
    edge_virtgpu_execbuffer_syncobj_t *syncobjs)
{
    if (!count) return address ? -EDGE_LINUX_EINVAL : 0;
    if (!address || !syncobjs ||
        count > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT ||
        stride < sizeof(syncobjs[0]))
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index)
        if (edge_virtgpu_copy_from(
                request, &syncobjs[index],
                address + (uint64_t)index * stride,
                sizeof(syncobjs[index])) < 0)
            return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_virtgpu_execbuffer_wait_inputs(
    uint64_t identity, const edge_virtgpu_execbuffer_syncobj_t *syncobjs,
    uint32_t count)
{
    for (;;) {
        uint64_t observed_sequence;
        int ready = 1;
        int result = 0;

        edge_virtgpu_lock();
        observed_sequence = __atomic_load_n(
            &g_edge_virtgpu_sync_sequence, __ATOMIC_ACQUIRE);
        for (uint32_t index = 0; index < count; ++index) {
            if (syncobjs[index].flags &
                ~EDGE_VIRTGPU_EXECBUF_SYNCOBJ_RESET) {
                result = -EDGE_LINUX_EINVAL;
                break;
            }
            result = edge_virtgpu_syncobj_point_ready_locked(
                identity, syncobjs[index].handle,
                syncobjs[index].point, 0);
            if (result < 0) break;
            if (!result) ready = 0;
        }
        edge_virtgpu_unlock();
        if (result < 0) return result;
        if (ready) return 0;
        result = kernel_runtime_wait_sequence(
            &g_edge_virtgpu_sync_sequence,
            observed_sequence, UINT64_MAX);
        if (result < 0) return -EDGE_LINUX_EINTR;
    }
}

static void edge_virtgpu_execbuffer_reset_inputs(
    uint64_t identity, const edge_virtgpu_execbuffer_syncobj_t *syncobjs,
    uint32_t count)
{
    edge_virtgpu_lock();
    for (uint32_t index = 0; index < count; ++index)
        if (syncobjs[index].flags & EDGE_VIRTGPU_EXECBUF_SYNCOBJ_RESET)
            (void)edge_virtgpu_syncobj_reset_locked(
                identity, syncobjs[index].handle);
    edge_virtgpu_unlock();
}

static int edge_virtgpu_execbuffer_wait_fence_fd(int32_t descriptor)
{
    int32_t file_id = kernel_anonymous_fd_descriptor_object_id(
        descriptor, KERNEL_ANONYMOUS_FD_DRM_SYNC);
    int result;

    if (file_id < 0 || edge_virtgpu_sync_file_retain(file_id) < 0)
        return -EDGE_LINUX_EINVAL;
    for (;;) {
        uint64_t observed_sequence;

        edge_virtgpu_lock();
        observed_sequence = __atomic_load_n(
            &g_edge_virtgpu_sync_sequence, __ATOMIC_ACQUIRE);
        result = edge_virtgpu_sync_file_status_locked(file_id, NULL);
        edge_virtgpu_unlock();
        if (result < 0) {
            result = -EDGE_LINUX_EINVAL;
            break;
        }
        if (result) {
            result = 0;
            break;
        }
        result = kernel_runtime_wait_sequence(
            &g_edge_virtgpu_sync_sequence,
            observed_sequence, UINT64_MAX);
        if (result < 0) {
            result = -EDGE_LINUX_EINTR;
            break;
        }
    }
    edge_virtgpu_sync_file_release(file_id);
    return result;
}

static int edge_virtgpu_execbuffer_create_output_fence(
    uint64_t identity, uint32_t *temporary_handle)
{
    edge_virtgpu_syncobj_handle_record_t *record;
    uint32_t handle = 0u;
    int file_id;
    int descriptor;
    int result;

    if (!temporary_handle) return -EDGE_LINUX_EINVAL;
    edge_virtgpu_lock();
    result = edge_virtgpu_syncobj_create_locked(identity, 0, &handle);
    record = result == 0 ?
        edge_virtgpu_syncobj_handle_locked(identity, handle) : NULL;
    file_id = record ? edge_virtgpu_sync_file_allocate_locked(
        record->object_id, 0u, 1) :
        (result < 0 ? result : -EDGE_LINUX_EINVAL);
    if (file_id < 0 && handle)
        (void)edge_virtgpu_syncobj_remove_handle_locked(identity, handle);
    edge_virtgpu_unlock();
    if (file_id < 0) return file_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_DRM_SYNC, file_id,
        EDGE_VIRTGPU_PRIME_RDWR, EDGE_VIRTGPU_PRIME_CLOEXEC);
    if (descriptor < 0) {
        edge_virtgpu_sync_file_release(file_id);
        edge_virtgpu_lock();
        (void)edge_virtgpu_syncobj_remove_handle_locked(identity, handle);
        edge_virtgpu_unlock();
        return descriptor;
    }
    *temporary_handle = handle;
    return descriptor;
}

static int edge_virtgpu_execbuffer_foreign_pending_locked(
    uint64_t identity, const uint32_t *handles, uint32_t handle_count,
    uint32_t context_id)
{
    for (uint32_t handle_index = 0;
         handle_index < handle_count; ++handle_index) {
        edge_virtgpu_resource_t *resource =
            edge_virtgpu_resource(identity, handles[handle_index]);
        uint32_t object_id = resource ?
            (uint32_t)edge_virtgpu_prime_object_id(resource) : 0u;

        if (!object_id) return -EDGE_LINUX_ENOENT;
        for (uint32_t submission_index = 0;
             submission_index < EDGE_VIRTGPU_SUBMISSION_COUNT;
             ++submission_index) {
            edge_virtgpu_submission_t *submission =
                &g_edge_virtgpu_submissions[submission_index];

            if (!submission->used ||
                submission->context_id == context_id)
                continue;
            for (uint32_t resource_index = 0;
                 resource_index < submission->resource_count;
                 ++resource_index)
                if (submission->resource_object_ids[resource_index] ==
                    object_id)
                    return 1;
        }
    }
    return 0;
}

static int edge_virtgpu_execbuffer_wait_foreign_submissions(
    uint64_t identity, const uint32_t *handles, uint32_t handle_count,
    uint32_t context_id, uint64_t deadline_us)
{
    for (;;) {
        uint64_t observed_sequence;
        int pending;
        int result;

        edge_virtgpu_lock();
        observed_sequence = __atomic_load_n(
            &g_edge_virtgpu_sync_sequence, __ATOMIC_ACQUIRE);
        pending = edge_virtgpu_execbuffer_foreign_pending_locked(
            identity, handles, handle_count, context_id);
        edge_virtgpu_unlock();
        if (pending <= 0) return pending;
        if (boottime_monotonic_us() >= deadline_us)
            return -EDGE_LINUX_EBUSY;
        result = kernel_runtime_wait_sequence(
            &g_edge_virtgpu_sync_sequence,
            observed_sequence, deadline_us);
        if (result < 0) return -EDGE_LINUX_EINTR;
    }
}

static int64_t edge_virtgpu_ioctl_execbuffer(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_execbuffer_t command;
    edge_virtgpu_client_t *client;
    uint32_t handles[EDGE_VIRTGPU_EXEC_HANDLE_COUNT];
    edge_virtgpu_execbuffer_syncobj_t *input_syncobjs = 0;
    edge_virtgpu_execbuffer_syncobj_t *output_syncobjs = 0;
    uint8_t *syncobj_storage = 0;
    uint32_t syncobj_pages = 0u;
    uint32_t syncobj_count;
    uint32_t output_fence_handle = 0u;
    int output_fence_descriptor = -1;
    uint64_t completion_id = 0u;
    uint64_t foreign_deadline_us;
    uint64_t observed_sequence;
    uint32_t submission_context_id = 0u;
    uint8_t *commands;
    uint32_t pages;
    int foreign_pending;
    int result;

    if (!request->argument ||
        edge_virtgpu_copy_from(
            request, &command, request->argument, sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags & ~EDGE_VIRTGPU_EXECBUF_FLAGS)
        return -EDGE_LINUX_EINVAL;
    if ((command.flags & EDGE_VIRTGPU_EXECBUF_RING_IDX) &&
        command.ring_idx != 0u)
        return -EDGE_LINUX_EINVAL;
    if ((!command.num_in_syncobjs && !command.num_out_syncobjs &&
         command.syncobj_stride) || !command.command || !command.size ||
        command.size > EDGE_VIRTGPU_MAX_COMMAND_SIZE ||
        command.size > g_edge_virtgpu_backend.info.maximum_command_size ||
        command.num_bo_handles > EDGE_VIRTGPU_EXEC_HANDLE_COUNT ||
        (command.num_bo_handles && !command.bo_handles))
        return -EDGE_LINUX_EINVAL;
    if (command.num_in_syncobjs > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT ||
        command.num_out_syncobjs > EDGE_VIRTGPU_SYNCOBJ_WAIT_COUNT)
        return -EDGE_LINUX_EINVAL;
    syncobj_count = command.num_in_syncobjs + command.num_out_syncobjs;
    if (syncobj_count) {
        syncobj_storage = edge_virtgpu_temporary_storage_allocate(
            (uint64_t)syncobj_count * sizeof(input_syncobjs[0]),
            &syncobj_pages);
        if (!syncobj_storage) return -EDGE_LINUX_ENOMEM;
        input_syncobjs =
            (edge_virtgpu_execbuffer_syncobj_t *)syncobj_storage;
        output_syncobjs = input_syncobjs + command.num_in_syncobjs;
    }
    result = edge_virtgpu_execbuffer_copy_syncobjs(
        request, command.in_syncobjs, command.num_in_syncobjs,
        command.syncobj_stride, input_syncobjs);
    if (result < 0) goto out_syncobjs;
    result = edge_virtgpu_execbuffer_copy_syncobjs(
        request, command.out_syncobjs, command.num_out_syncobjs,
        command.syncobj_stride, output_syncobjs);
    if (result < 0) goto out_syncobjs;
    result = edge_virtgpu_execbuffer_wait_inputs(
        identity, input_syncobjs, command.num_in_syncobjs);
    if (result < 0) goto out_syncobjs;
    edge_virtgpu_execbuffer_reset_inputs(
        identity, input_syncobjs, command.num_in_syncobjs);
    if (command.flags & EDGE_VIRTGPU_EXECBUF_FENCE_FD_IN) {
        result = edge_virtgpu_execbuffer_wait_fence_fd(command.fence_fd);
        if (result < 0) goto out_syncobjs;
    }
    if (command.num_bo_handles &&
        edge_virtgpu_copy_from(
            request, handles, command.bo_handles,
            (uint64_t)command.num_bo_handles * sizeof(handles[0])) < 0)
        {
            result = -EDGE_LINUX_EFAULT;
            goto out_syncobjs;
        }
    edge_virtgpu_lock();
    client = edge_virtgpu_client(identity, 1);
    result = client ? edge_virtgpu_context_ensure(client) :
        -EDGE_LINUX_ENOSPC;
    if (result == 0) submission_context_id = client->context_id;
    for (uint32_t index = 0;
         result == 0 && index < command.num_bo_handles; ++index)
        if (!edge_virtgpu_resource(identity, handles[index]))
            result = -EDGE_LINUX_ENOENT;
    edge_virtgpu_unlock();
    if (result < 0) goto out_syncobjs;
    foreign_deadline_us = boottime_monotonic_us() + 15000000u;
    result = edge_virtgpu_execbuffer_wait_foreign_submissions(
        identity, handles, command.num_bo_handles,
        submission_context_id, foreign_deadline_us);
    if (result < 0) goto out_syncobjs;
    pages = (command.size + EDGE_VIRTGPU_PAGE_SIZE - 1u) /
        EDGE_VIRTGPU_PAGE_SIZE;
    commands = arch_vm_alloc_pages(pages);
    if (!commands) {
        result = -EDGE_LINUX_ENOMEM;
        goto out_syncobjs;
    }
    if (edge_virtgpu_copy_from(
            request, commands, command.command, command.size) < 0) {
        edge_virtgpu_storage_release(commands, pages);
        result = -EDGE_LINUX_EFAULT;
        goto out_syncobjs;
    }
    if (command.flags & EDGE_VIRTGPU_EXECBUF_FENCE_FD_OUT) {
        output_fence_descriptor =
            edge_virtgpu_execbuffer_create_output_fence(
                identity, &output_fence_handle);
        if (output_fence_descriptor < 0) {
            edge_virtgpu_storage_release(commands, pages);
            result = output_fence_descriptor;
            goto out_syncobjs;
        }
    }

reserve_submission:
    edge_virtgpu_lock();
    client = edge_virtgpu_client(identity, 1);
    result = client ? edge_virtgpu_context_ensure(client) :
        -EDGE_LINUX_ENOSPC;
    foreign_pending = result == 0 ?
        edge_virtgpu_execbuffer_foreign_pending_locked(
            identity, handles, command.num_bo_handles,
            client->context_id) : result;
    if (foreign_pending != 0) {
        observed_sequence = __atomic_load_n(
            &g_edge_virtgpu_sync_sequence, __ATOMIC_ACQUIRE);
        edge_virtgpu_unlock();
        if (foreign_pending < 0) {
            result = foreign_pending;
            goto release_commands;
        }
        if (boottime_monotonic_us() >= foreign_deadline_us) {
            result = -EDGE_LINUX_EBUSY;
            goto release_commands;
        }
        result = kernel_runtime_wait_sequence(
            &g_edge_virtgpu_sync_sequence,
            observed_sequence, foreign_deadline_us);
        if (result < 0) {
            result = -EDGE_LINUX_EINTR;
            goto release_commands;
        }
        goto reserve_submission;
    }
    for (uint32_t index = 0;
         result == 0 && index < command.num_bo_handles; ++index)
        if (!edge_virtgpu_resource(identity, handles[index]))
            result = -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0;
         result == 0 && index < command.num_out_syncobjs; ++index) {
        if (output_syncobjs[index].flags) {
            result = -EDGE_LINUX_EINVAL;
            break;
        }
        if (!edge_virtgpu_syncobj_locked(
                identity, output_syncobjs[index].handle)) {
            result = -EDGE_LINUX_EINVAL;
            break;
        }
    }
    if (result == 0) {
        edge_virtgpu_submission_t *submission =
            edge_virtgpu_submission_allocate_locked(client->context_id);

        if (!submission) {
            result = -EDGE_LINUX_ENOSPC;
        } else {
            submission->commands = commands;
            submission->command_pages = pages;
            submission->syncobj_storage = syncobj_storage;
            submission->syncobj_pages = syncobj_pages;
            submission->outputs = output_syncobjs;
            submission->output_count = 0u;
            completion_id = submission->completion_id;
            submission_context_id = submission->context_id;
            for (uint32_t index = 0;
                 index < command.num_bo_handles; ++index) {
                edge_virtgpu_resource_t *resource =
                    edge_virtgpu_resource(identity, handles[index]);
                uint32_t object_id = resource ?
                    (uint32_t)edge_virtgpu_prime_object_id(resource) : 0u;
                int duplicate = 0;

                for (uint32_t prior = 0;
                     prior < submission->resource_count; ++prior)
                    if (submission->resource_object_ids[prior] ==
                        object_id) {
                        duplicate = 1;
                        break;
                    }
                if (duplicate) continue;
                if (!resource || !object_id ||
                    resource->submission_refs == UINT32_MAX) {
                    result = -EDGE_LINUX_EOVERFLOW;
                    break;
                }
                resource->submission_refs++;
                submission->resource_object_ids[
                    submission->resource_count++] = object_id;
            }
            for (uint32_t index = 0;
                 index < command.num_out_syncobjs; ++index) {
                edge_virtgpu_syncobj_handle_record_t *record =
                    edge_virtgpu_syncobj_handle_locked(
                        identity, output_syncobjs[index].handle);
                edge_virtgpu_syncobj_t *object = record ?
                    edge_virtgpu_syncobj_object_locked(
                        record->object_id) : NULL;

                if (!object || object->references == UINT16_MAX) {
                    result = -EDGE_LINUX_EOVERFLOW;
                    break;
                }
                object->references++;
                output_syncobjs[index].handle = record->object_id;
                submission->output_count++;
            }
            if (result == 0 && output_fence_handle) {
                edge_virtgpu_syncobj_handle_record_t *record =
                    edge_virtgpu_syncobj_handle_locked(
                        identity, output_fence_handle);
                edge_virtgpu_syncobj_t *object = record ?
                    edge_virtgpu_syncobj_object_locked(
                        record->object_id) : NULL;

                if (!object || object->references == UINT16_MAX) {
                    result = -EDGE_LINUX_EOVERFLOW;
                } else {
                    object->references++;
                    submission->output_fence_object_id =
                        record->object_id;
                }
            }
            if (result == 0) {
                for (uint32_t index = 0;
                     index < submission->output_count; ++index) {
                    edge_virtgpu_syncobj_t *object =
                        edge_virtgpu_syncobj_object_locked(
                            submission->outputs[index].handle);
                    uint64_t point = submission->outputs[index].point ?
                        submission->outputs[index].point : 1u;

                    if (object && point > object->available_point)
                        object->available_point = point;
                    edge_virtgpu_syncobj_notify_locked(
                        submission->outputs[index].handle);
                }
                if (submission->output_fence_object_id) {
                    edge_virtgpu_syncobj_t *object =
                        edge_virtgpu_syncobj_object_locked(
                            submission->output_fence_object_id);

                    if (object && object->available_point < 1u)
                        object->available_point = 1u;
                    edge_virtgpu_syncobj_notify_locked(
                        submission->output_fence_object_id);
                }
            }
            if (result < 0) {
                edge_virtgpu_submission_release_references_locked(
                    submission, 0);
                memset(submission, 0, sizeof(*submission));
                completion_id = 0u;
            }
        }
    }
    if (result == 0 && output_fence_handle) {
        (void)edge_virtgpu_syncobj_remove_handle_locked(
            identity, output_fence_handle);
        output_fence_handle = 0u;
    }
    edge_virtgpu_unlock();
    if (result == 0 &&
        g_edge_virtgpu_backend.operations.submit_3d(
            g_edge_virtgpu_backend.context, submission_context_id,
            commands, command.size, completion_id) < 0) {
        edge_virtgpu_submission_finish(completion_id, 0);
        result = -EDGE_LINUX_EIO;
    }
    if (result == 0) {
        commands = NULL;
        pages = 0u;
        syncobj_storage = NULL;
        syncobj_pages = 0u;
    }
release_commands:
    edge_virtgpu_storage_release(commands, pages);
    if (result == 0 && output_fence_descriptor >= 0) {
        command.fence_fd = output_fence_descriptor;
        if (edge_virtgpu_copy_to(
                request, request->argument,
                &command, sizeof(command)) < 0)
            result = -EDGE_LINUX_EFAULT;
    }
out_syncobjs:
    if (result < 0 && output_fence_descriptor >= 0)
        (void)kernel_fd_close(output_fence_descriptor);
    if (output_fence_handle) {
        edge_virtgpu_lock();
        (void)edge_virtgpu_syncobj_remove_handle_locked(
            identity, output_fence_handle);
        edge_virtgpu_unlock();
    }
    edge_virtgpu_storage_release(syncobj_storage, syncobj_pages);
    return result;
}

static int edge_virtgpu_resource_wait_idle(
    uint32_t object_id, uint64_t deadline_us)
{
    for (;;) {
        edge_virtgpu_resource_t *resource;
        uint64_t observed_sequence;
        int result;

        edge_virtgpu_lock();
        resource = edge_virtgpu_prime_resource((int32_t)object_id);
        observed_sequence = __atomic_load_n(
            &g_edge_virtgpu_sync_sequence, __ATOMIC_ACQUIRE);
        if (!resource || !resource->submission_refs) {
            result = resource ? 0 : -EDGE_LINUX_ENOENT;
            edge_virtgpu_unlock();
            return result;
        }
        edge_virtgpu_unlock();
        if (boottime_monotonic_us() >= deadline_us)
            return -EDGE_LINUX_EBUSY;
        result = kernel_runtime_wait_sequence(
            &g_edge_virtgpu_sync_sequence,
            observed_sequence, deadline_us);
        if (result < 0) return -EDGE_LINUX_EINTR;
    }
}

static void edge_virtgpu_resource_wait_release(uint32_t object_id)
{
    edge_virtgpu_resource_t *resource;

    edge_virtgpu_lock();
    resource = edge_virtgpu_prime_resource((int32_t)object_id);
    if (resource && resource->wait_refs) {
        resource->wait_refs--;
        edge_virtgpu_resource_maybe_release(resource);
    }
    edge_virtgpu_unlock();
}

static int64_t edge_virtgpu_ioctl_wait(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_virtgpu_wait_t command;
    edge_virtgpu_resource_t *resource;
    uint32_t object_id;
    int result;

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
    if (!resource->submission_refs) {
        edge_virtgpu_unlock();
        return 0;
    }
    if (command.flags & EDGE_VIRTGPU_WAIT_NOWAIT) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_EBUSY;
    }
    if (resource->wait_refs == UINT32_MAX) {
        edge_virtgpu_unlock();
        return -EDGE_LINUX_EOVERFLOW;
    }
    object_id = (uint32_t)edge_virtgpu_prime_object_id(resource);
    resource->wait_refs++;
    edge_virtgpu_unlock();
    result = edge_virtgpu_resource_wait_idle(
        object_id, boottime_monotonic_us() + 15000000u);
    edge_virtgpu_resource_wait_release(object_id);
    return result;
}

static int64_t edge_virtgpu_ioctl_get_caps(
    const kernel_ioctl_request_t *request) {
    edge_virtgpu_get_caps_t command;
    uint8_t *data;
    void *backend_context;
    int (*get_capset)(
        void *, uint32_t, uint32_t, void *, uint32_t, uint32_t *);
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
    get_capset = g_edge_virtgpu_backend.operations.get_capset;
    backend_context = g_edge_virtgpu_backend.context;
    edge_virtgpu_unlock();
    result = get_capset ? get_capset(
        backend_context, command.cap_set_id,
        command.cap_set_version, data, transfer_size, &actual) : -1;
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
        result = -EDGE_LINUX_EEXIST;
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
    void *backend_context;
    int (*resource_attach)(void *, uint32_t, uint32_t);
    int32_t object_id;
    uint32_t context_id;
    uint32_t resource_id;
    int installed = 0;
    int result;

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
        if (!candidate->used || !candidate->backend_ready ||
            candidate->owner != identity)
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
        handle_record->backend_creating = 1u;
        resource_attach =
            g_edge_virtgpu_backend.operations.resource_attach;
        backend_context = g_edge_virtgpu_backend.context;
        context_id = handle_record->context_id;
        resource_id = resource->resource_id;
        if (!resource_attach) {
            memset(handle_record, 0, sizeof(*handle_record));
            edge_virtgpu_unlock();
            return -EDGE_LINUX_EIO;
        }

        edge_virtgpu_unlock();
        result = resource_attach(
            backend_context, context_id, resource_id);
        edge_virtgpu_lock();
        resource = edge_virtgpu_prime_resource(object_id);
        if (result < 0 || !resource || !resource->backend_ready ||
            !handle_record->used ||
            handle_record->owner != identity ||
            handle_record->context_id != context_id ||
            handle_record->backing_object_id != object_id ||
            !handle_record->backend_creating) {
            if (handle_record->used &&
                handle_record->owner == identity &&
                handle_record->context_id == context_id &&
                handle_record->backing_object_id == object_id)
                memset(handle_record, 0, sizeof(*handle_record));
            edge_virtgpu_unlock();
            return -EDGE_LINUX_EIO;
        }
        handle_record->backend_creating = 0u;
        handle_record->backend_ready = 1u;
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
    return __atomic_load_n(
        &g_edge_virtgpu_backend.owner, __ATOMIC_ACQUIRE) != 0;
}

int edge_virtgpu_framebuffer_available(void) {
    return __atomic_load_n(
               &g_edge_virtgpu_backend.owner,
               __ATOMIC_ACQUIRE) != 0 &&
        g_edge_virtgpu_backend.operations.present_resource != 0;
}

static void edge_virtgpu_sync_files_notify_ready(void)
{
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNC_FILE_COUNT; ++index) {
        int ready;

        edge_virtgpu_lock();
        ready = g_edge_virtgpu_sync_files[index].used &&
            edge_virtgpu_sync_file_status_locked(
                (int32_t)index + 1, NULL) > 0;
        edge_virtgpu_unlock();
        if (ready) kernel_drm_sync_state_changed((int32_t)index + 1);
    }
}

const char *edge_virtgpu_driver_name(void) {
    return edge_virtgpu_available() ? "virtio_gpu" : 0;
}

int64_t edge_virtgpu_syncobj_ioctl(
    uint64_t identity, const kernel_ioctl_request_t *request)
{
    int64_t result;

    if (!identity || !request) return -EDGE_LINUX_EBADF;
    switch (request->command) {
        case EDGE_DRM_IOCTL_SYNCOBJ_CREATE:
            result = edge_virtgpu_syncobj_create_ioctl(identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_DESTROY:
            result = edge_virtgpu_syncobj_destroy_ioctl(identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_WAIT:
            result = edge_virtgpu_syncobj_wait_ioctl(identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_RESET:
            result = edge_virtgpu_syncobj_array_ioctl(
                identity, request, 0);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_SIGNAL:
            result = edge_virtgpu_syncobj_array_ioctl(
                identity, request, 1);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT:
            result = edge_virtgpu_syncobj_timeline_wait_ioctl(
                identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_QUERY:
            result = edge_virtgpu_syncobj_query_ioctl(identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_TRANSFER:
            result = edge_virtgpu_syncobj_transfer_ioctl(identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL:
            result = edge_virtgpu_syncobj_timeline_signal_ioctl(
                identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD:
            result = edge_virtgpu_syncobj_handle_to_fd_ioctl(
                identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE:
            result = edge_virtgpu_syncobj_fd_to_handle_ioctl(
                identity, request);
            break;
        case EDGE_DRM_IOCTL_SYNCOBJ_EVENTFD:
            result = edge_virtgpu_syncobj_eventfd_ioctl(identity, request);
            break;
        default:
            return -EDGE_LINUX_ENOTTY;
    }
    if (result >= 0) edge_virtgpu_sync_files_notify_ready();
    return result;
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
        {
            int64_t result = edge_virtgpu_ioctl_execbuffer(
                identity, request);
            if (result >= 0) edge_virtgpu_sync_files_notify_ready();
            return result;
        }
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
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNCOBJ_EVENT_COUNT; ++index) {
        edge_virtgpu_syncobj_event_t *event =
            &g_edge_virtgpu_syncobj_events[index];

        if (!event->used || event->owner != identity) continue;
        kernel_eventfd_release(event->event_id);
        memset(event, 0, sizeof(*event));
    }
    for (uint32_t index = 0;
         index < EDGE_VIRTGPU_SYNCOBJ_HANDLE_COUNT; ++index) {
        edge_virtgpu_syncobj_handle_record_t *record =
            &g_edge_virtgpu_syncobj_handles[index];
        uint32_t object_id;

        if (!record->used || record->owner != identity) continue;
        object_id = record->object_id;
        memset(record, 0, sizeof(*record));
        edge_virtgpu_syncobj_release_object_locked(object_id);
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

int edge_virtgpu_sync_file_retain(int32_t object_id)
{
    int result;

    edge_virtgpu_lock();
    result = edge_virtgpu_sync_file_retain_locked(object_id);
    edge_virtgpu_unlock();
    return result;
}

void edge_virtgpu_sync_file_release(int32_t object_id)
{
    edge_virtgpu_lock();
    edge_virtgpu_sync_file_release_locked(object_id);
    edge_virtgpu_unlock();
}

int edge_virtgpu_sync_file_ready(int32_t object_id)
{
    int result = -EDGE_LINUX_EBADF;

    edge_virtgpu_lock();
    if (edge_virtgpu_sync_file_locked(object_id))
        result = edge_virtgpu_sync_file_status_locked(object_id, NULL);
    edge_virtgpu_unlock();
    return result;
}

int64_t edge_virtgpu_sync_file_ioctl(
    int32_t object_id, const kernel_ioctl_request_t *request)
{
    if (!request) return -EDGE_LINUX_EINVAL;
    if (request->command == EDGE_SYNC_IOC_FILE_INFO) {
        edge_sync_file_info_t info;
        char name[32];
        uint32_t leaf_count;
        int status;

        if (!request->argument || edge_virtgpu_copy_from(
                request, &info, request->argument, sizeof(info)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (info.flags || info.pad) return -EDGE_LINUX_EINVAL;
        edge_virtgpu_lock();
        {
            edge_virtgpu_sync_file_t *file =
                edge_virtgpu_sync_file_locked(object_id);

            if (!file || !file->sync_file) {
                edge_virtgpu_unlock();
                return -EDGE_LINUX_EINVAL;
            }
            leaf_count = file->leaf_count;
            memcpy(name, file->name, sizeof(name));
            status = edge_virtgpu_sync_file_status_locked(
                object_id, NULL);
        }
        edge_virtgpu_unlock();
        if (status < 0) return status;
        if (info.num_fences && info.num_fences < leaf_count)
            return -EDGE_LINUX_EINVAL;
        if (info.num_fences) {
            for (uint32_t index = 0; index < leaf_count; ++index) {
                edge_sync_fence_info_t fence_info;
                int result;

                edge_virtgpu_lock();
                result = edge_virtgpu_sync_file_leaf_info_locked(
                    object_id, index, &fence_info);
                edge_virtgpu_unlock();
                if (result < 0) return result;
                if (edge_virtgpu_copy_to(
                        request,
                        info.sync_fence_info +
                            (uint64_t)index * sizeof(fence_info),
                        &fence_info, sizeof(fence_info)) < 0)
                    return -EDGE_LINUX_EFAULT;
            }
        }
        memcpy(info.name, name, sizeof(info.name));
        info.status = status;
        info.num_fences = leaf_count;
        if (edge_virtgpu_copy_to(
                request, request->argument, &info, sizeof(info)) < 0)
            return -EDGE_LINUX_EFAULT;
        return 0;
    }
    if (request->command == EDGE_SYNC_IOC_MERGE) {
        edge_sync_merge_data_t merge;
        int32_t second_id;
        int merged_id;
        int descriptor;

        if (!request->argument || edge_virtgpu_copy_from(
                request, &merge, request->argument, sizeof(merge)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (merge.flags || merge.pad) return -EDGE_LINUX_EINVAL;
        merge.name[sizeof(merge.name) - 1u] = 0;
        second_id = kernel_anonymous_fd_descriptor_object_id(
            merge.fd2, KERNEL_ANONYMOUS_FD_DRM_SYNC);
        if (second_id < 0) return -EDGE_LINUX_ENOENT;
        edge_virtgpu_lock();
        merged_id = edge_virtgpu_sync_file_merge_locked(
            object_id, second_id, merge.name);
        edge_virtgpu_unlock();
        if (merged_id < 0) return merged_id;
        descriptor = kernel_anonymous_fd_install_descriptor(
            KERNEL_ANONYMOUS_FD_DRM_SYNC, merged_id,
            EDGE_VIRTGPU_PRIME_RDWR, EDGE_VIRTGPU_PRIME_CLOEXEC);
        if (descriptor < 0) {
            edge_virtgpu_sync_file_release(merged_id);
            return descriptor;
        }
        merge.fence = descriptor;
        if (edge_virtgpu_copy_to(
                request, request->argument, &merge, sizeof(merge)) < 0) {
            (void)kernel_fd_close(descriptor);
            return -EDGE_LINUX_EFAULT;
        }
        return 0;
    }
    if (request->command == EDGE_SYNC_IOC_SET_DEADLINE) {
        edge_sync_set_deadline_t deadline;
        edge_virtgpu_sync_file_t *file;
        int valid;

        if (!request->argument || edge_virtgpu_copy_from(
                request, &deadline, request->argument,
                sizeof(deadline)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (deadline.pad) return -EDGE_LINUX_EINVAL;
        edge_virtgpu_lock();
        file = edge_virtgpu_sync_file_locked(object_id);
        valid = file && file->sync_file;
        if (valid) file->deadline_ns = deadline.deadline_ns;
        edge_virtgpu_unlock();
        return valid ? 0 : -EDGE_LINUX_EINVAL;
    }
    return -EDGE_LINUX_ENOTTY;
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

static void edge_virtgpu_pending_present_release_locked(void)
{
    edge_virtgpu_resource_t *resource;

    if (!g_edge_virtgpu_pending_present.used) return;
    resource = edge_virtgpu_prime_resource(
        (int32_t)g_edge_virtgpu_pending_present.resource_object_id);
    memset(&g_edge_virtgpu_pending_present, 0,
           sizeof(g_edge_virtgpu_pending_present));
    if (resource && resource->present_refs) {
        resource->present_refs--;
        edge_virtgpu_resource_maybe_release(resource);
    }
}

static int edge_virtgpu_pending_present_queue_locked(
    edge_virtgpu_resource_t *resource,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    uint32_t object_id;

    object_id = resource ?
        (uint32_t)edge_virtgpu_prime_object_id(resource) : 0u;
    if (!object_id) return -EDGE_LINUX_ENOENT;
    if (g_edge_virtgpu_pending_present.used &&
        g_edge_virtgpu_pending_present.resource_object_id == object_id) {
        uint32_t left = x < g_edge_virtgpu_pending_present.x ?
            x : g_edge_virtgpu_pending_present.x;
        uint32_t top = y < g_edge_virtgpu_pending_present.y ?
            y : g_edge_virtgpu_pending_present.y;
        uint32_t right = x + width;
        uint32_t bottom = y + height;
        uint32_t pending_right = g_edge_virtgpu_pending_present.x +
            g_edge_virtgpu_pending_present.width;
        uint32_t pending_bottom = g_edge_virtgpu_pending_present.y +
            g_edge_virtgpu_pending_present.height;

        if (pending_right > right) right = pending_right;
        if (pending_bottom > bottom) bottom = pending_bottom;
        g_edge_virtgpu_pending_present.x = left;
        g_edge_virtgpu_pending_present.y = top;
        g_edge_virtgpu_pending_present.width = right - left;
        g_edge_virtgpu_pending_present.height = bottom - top;
        return 0;
    }
    if (resource->present_refs == UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    edge_virtgpu_pending_present_release_locked();
    resource->present_refs++;
    g_edge_virtgpu_pending_present.used = 1u;
    g_edge_virtgpu_pending_present.resource_object_id = object_id;
    g_edge_virtgpu_pending_present.x = x;
    g_edge_virtgpu_pending_present.y = y;
    g_edge_virtgpu_pending_present.width = width;
    g_edge_virtgpu_pending_present.height = height;
    return 0;
}

static void edge_virtgpu_dispatch_ready_present(void)
{
    edge_virtgpu_pending_present_t pending;
    edge_virtgpu_resource_t *resource;
    int (*present_resource)(
        void *, uint32_t, uint32_t, uint32_t,
        uint32_t, uint32_t, uint32_t, uint32_t);
    void *backend_context;
    uint32_t resource_id;
    uint32_t resource_width;
    uint32_t resource_height;

    memset(&pending, 0, sizeof(pending));
    edge_virtgpu_lock();
    resource = g_edge_virtgpu_pending_present.used ?
        edge_virtgpu_prime_resource(
            (int32_t)g_edge_virtgpu_pending_present.resource_object_id) : 0;
    if (!resource || resource->submission_refs ||
        !g_edge_virtgpu_backend.operations.present_resource) {
        if (edge_virtgpu_present_diagnostic_enabled())
            console_printf(
                "[virgl-diag] present-dispatch pending=%u object=%u resource=%u submissions=%u backend=%u\n",
                g_edge_virtgpu_pending_present.used ? 1u : 0u,
                g_edge_virtgpu_pending_present.resource_object_id,
                resource ? resource->resource_id : 0u,
                resource ? resource->submission_refs : 0u,
                g_edge_virtgpu_backend.operations.present_resource ? 1u : 0u);
        if (!resource) edge_virtgpu_pending_present_release_locked();
        edge_virtgpu_unlock();
        return;
    }
    pending = g_edge_virtgpu_pending_present;
    memset(&g_edge_virtgpu_pending_present, 0,
           sizeof(g_edge_virtgpu_pending_present));
    present_resource = g_edge_virtgpu_backend.operations.present_resource;
    backend_context = g_edge_virtgpu_backend.context;
    resource_id = resource->resource_id;
    resource_width = resource->width;
    resource_height = resource->height;
    edge_virtgpu_unlock();

    if (edge_virtgpu_present_diagnostic_enabled())
        console_printf(
            "[virgl-diag] present-submit object=%u resource=%u %ux%u rect=%u,%u %ux%u\n",
            pending.resource_object_id, resource_id,
            resource_width, resource_height, pending.x, pending.y,
            pending.width, pending.height);
    (void)present_resource(
        backend_context, resource_id, resource_width, resource_height,
        pending.x, pending.y, pending.width, pending.height);

    edge_virtgpu_lock();
    resource = edge_virtgpu_prime_resource(
        (int32_t)pending.resource_object_id);
    if (resource && resource->present_refs) {
        resource->present_refs--;
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
        result = edge_virtgpu_pending_present_queue_locked(
            backing, x, y, width, height);
    if (edge_virtgpu_present_diagnostic_enabled())
        console_printf(
            "[virgl-diag] framebuffer-present owner=%llu handle=%u resource=%u backing=%u fbrefs=%u submissions=%u result=%d rect=%u,%u %ux%u\n",
            (unsigned long long)identity, handle,
            resource ? resource->resource_id : 0u,
            backing ? backing->resource_id : 0u,
            resource ? resource->framebuffer_refs : 0u,
            backing ? backing->submission_refs : 0u,
            result, x, y, width, height);
    edge_virtgpu_unlock();
    if (result == 0) edge_virtgpu_dispatch_ready_present();
    return result;
}

int edge_virtgpu_framebuffer_reset(void) {
    int result;
    int (*present_resource)(
        void *, uint32_t, uint32_t, uint32_t,
        uint32_t, uint32_t, uint32_t, uint32_t);
    void *backend_context;

    edge_virtgpu_lock();
    edge_virtgpu_pending_present_release_locked();
    present_resource = g_edge_virtgpu_backend.operations.present_resource;
    backend_context = g_edge_virtgpu_backend.context;
    edge_virtgpu_unlock();
    result = present_resource ? present_resource(
        backend_context, 0u, 0u, 0u, 0u, 0u, 0u, 0u) : -1;
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
        *kernel_address = edge_virtgpu_backing_page(
            &backing->backing, page_index);
        result = *kernel_address ? 0 : -EDGE_LINUX_EIO;
        break;
    }
    edge_virtgpu_unlock();
    return result;
}
