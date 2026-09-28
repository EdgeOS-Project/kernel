/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS object and usercopy boundary for the IOMMUFD ABI. */

#include "kernel/edge_iommufd_runtime.h"
#include "kernel/linux_errno.h"

#define EDGE_IOMMUFD_MAX_CONTEXTS 16u
#define EDGE_IOMMUFD_MAX_IOAS 32u
#define EDGE_IOMMUFD_MAX_MAPS 128u
#define EDGE_IOMMUFD_MAX_ALLOWED_RANGES 8u
#define EDGE_IOMMUFD_MAX_ATTACHMENTS 64u
#define EDGE_IOMMUFD_MAX_DEVICES 64u
#define EDGE_IOMMUFD_MAX_HWPTS 64u
#define EDGE_IOMMUFD_PAGE_SIZE UINT64_C(4096)

typedef struct edge_iommufd_mapping {
    uint8_t live;
    uint8_t file_backed;
    uint8_t reserved[2];
    uint32_t flags;
    uint32_t ioas_id;
    uint32_t padding;
    uint64_t user_va;
    uint64_t iova;
    uint64_t length;
    uint64_t file_cookie;
} edge_iommufd_mapping_t;

typedef struct edge_iommufd_ioas {
    uint8_t live;
    uint8_t huge_pages;
    uint16_t allowed_count;
    uint32_t id;
    edge_iommu_iova_range_t allowed[EDGE_IOMMUFD_MAX_ALLOWED_RANGES];
} edge_iommufd_ioas_t;

typedef struct edge_iommufd_context {
    uint8_t live;
    uint8_t rlimit_mode;
    uint16_t reserved;
    uint32_t generation;
    uint32_t references;
    uint32_t next_id;
    uint32_t vfio_ioas_id;
    uint32_t devices[EDGE_IOMMUFD_MAX_DEVICES];
    struct {
        uint8_t live;
        uint8_t dirty_enabled;
        uint16_t references;
        uint32_t id;
        uint32_t dev_id;
        uint32_t ioas_id;
        uint32_t flags;
    } hwpts[EDGE_IOMMUFD_MAX_HWPTS];
    edge_iommufd_ioas_t ioas[EDGE_IOMMUFD_MAX_IOAS];
    edge_iommufd_mapping_t maps[EDGE_IOMMUFD_MAX_MAPS];
} edge_iommufd_context_t;

typedef struct edge_iommufd_attachment {
    uint8_t live;
    uint8_t reserved[3];
    uint32_t id;
    uint32_t ioas_id;
    edge_iommufd_handle_t owner;
    kernel_edge_iommufd_ioas_ops_t ops;
    void *context;
} edge_iommufd_attachment_t;

static edge_iommufd_context_t g_contexts[EDGE_IOMMUFD_MAX_CONTEXTS];
static const kernel_edge_iommufd_descriptor_backend_ops_t *g_descriptors;
static void *g_descriptor_context;
static const kernel_edge_iommufd_file_backend_ops_t *g_files;
static void *g_file_context;
static volatile uint32_t g_lock;
static uint8_t g_unmap_scratch[EDGE_IOMMUFD_MAX_MAPS];
static uint64_t g_file_cookie_scratch[EDGE_IOMMUFD_MAX_MAPS];
static edge_iommufd_attachment_t
    g_attachments[EDGE_IOMMUFD_MAX_ATTACHMENTS];
static uint32_t g_next_attachment_id = 1u;

static edge_iommufd_ioas_t *ioas_find(edge_iommufd_context_t *context,
                                      uint32_t id);

static int handle_equal(edge_iommufd_handle_t left,
                        edge_iommufd_handle_t right) {
    return left.slot == right.slot && left.generation == right.generation;
}

static int mapping_notify_map(edge_iommufd_handle_t owner,
                              const edge_iommufd_mapping_t *map) {
    uint32_t completed = 0;

    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_ATTACHMENTS; ++index) {
        edge_iommufd_attachment_t *attachment = &g_attachments[index];
        int status;
        if (!attachment->live || !handle_equal(attachment->owner, owner) ||
            attachment->ioas_id != map->ioas_id)
            continue;
        status = attachment->ops.map(attachment->context, map->iova,
            map->user_va, map->length, map->flags);
        if (status < 0) {
            for (uint32_t rollback = 0;
                 rollback < EDGE_IOMMUFD_MAX_ATTACHMENTS && completed != 0;
                 ++rollback) {
                edge_iommufd_attachment_t *prior = &g_attachments[rollback];
                if (!prior->live || !handle_equal(prior->owner, owner) ||
                    prior->ioas_id != map->ioas_id)
                    continue;
                (void)prior->ops.unmap(prior->context, map->iova,
                    map->length);
                --completed;
            }
            return status;
        }
        ++completed;
    }
    return 0;
}

static int mapping_notify_unmap(edge_iommufd_handle_t owner,
                                const edge_iommufd_mapping_t *map) {
    uint32_t completed = 0;

    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_ATTACHMENTS; ++index) {
        edge_iommufd_attachment_t *attachment = &g_attachments[index];
        int status;
        if (!attachment->live || !handle_equal(attachment->owner, owner) ||
            attachment->ioas_id != map->ioas_id)
            continue;
        status = attachment->ops.unmap(
            attachment->context, map->iova, map->length);
        if (status < 0) {
            for (uint32_t rollback = 0;
                 rollback < EDGE_IOMMUFD_MAX_ATTACHMENTS && completed != 0;
                 ++rollback) {
                edge_iommufd_attachment_t *prior = &g_attachments[rollback];
                if (!prior->live || !handle_equal(prior->owner, owner) ||
                    prior->ioas_id != map->ioas_id)
                    continue;
                (void)prior->ops.map(prior->context, map->iova,
                    map->user_va, map->length, map->flags);
                --completed;
            }
            return status;
        }
        ++completed;
    }
    return 0;
}

static void iommufd_lock(void) {
    while (__atomic_exchange_n(&g_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void iommufd_unlock(void) {
    __atomic_store_n(&g_lock, 0u, __ATOMIC_RELEASE);
}

int kernel_edge_iommufd_descriptor_backend_register(
        const kernel_edge_iommufd_descriptor_backend_ops_t *ops,
        void *context) {
    if (!ops || !ops->install || !ops->resolve)
        return -EDGE_LINUX_EINVAL;
    g_descriptors = ops;
    g_descriptor_context = context;
    return 0;
}

int kernel_edge_iommufd_file_backend_register(
        const kernel_edge_iommufd_file_backend_ops_t *ops, void *context) {
    if (!ops || !ops->acquire || !ops->retain || !ops->release ||
        !ops->change_process)
        return -EDGE_LINUX_EINVAL;
    g_files = ops;
    g_file_context = context;
    return 0;
}

static int context_resolve(edge_iommufd_handle_t handle,
                           edge_iommufd_context_t **context_out) {
    edge_iommufd_context_t *context;
    if (!context_out || handle.slot >= EDGE_IOMMUFD_MAX_CONTEXTS)
        return -EDGE_LINUX_EBADF;
    context = &g_contexts[handle.slot];
    if (!context->live || context->generation != handle.generation)
        return -EDGE_LINUX_EBADF;
    *context_out = context;
    return 0;
}

static void context_clear(edge_iommufd_context_t *context) {
    context->rlimit_mode = 0;
    context->next_id = 1;
    context->vfio_ioas_id = 0;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_DEVICES; ++index)
        context->devices[index] = 0;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_HWPTS; ++index)
        context->hwpts[index].live = 0;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_IOAS; ++index)
        context->ioas[index].live = 0;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (context->maps[index].live &&
            context->maps[index].file_backed && g_files)
            g_files->release(g_file_context,
                             context->maps[index].file_cookie);
        context->maps[index].live = 0;
    }
}

int kernel_edge_iommufd_open(void) {
    edge_iommufd_handle_t handle;
    int descriptor = -EDGE_LINUX_ENOSPC;
    if (!g_descriptors) return -EDGE_LINUX_ENODEV;
    iommufd_lock();
    for (uint32_t slot = 0; slot < EDGE_IOMMUFD_MAX_CONTEXTS; ++slot) {
        edge_iommufd_context_t *context = &g_contexts[slot];
        if (context->live) continue;
        ++context->generation;
        if (context->generation == 0) ++context->generation;
        context->live = 1;
        context->references = 1;
        context_clear(context);
        handle.slot = slot;
        handle.generation = context->generation;
        descriptor = g_descriptors->install(g_descriptor_context, handle);
        if (descriptor < 0) {
            context->live = 0;
            context->references = 0;
        }
        break;
    }
    iommufd_unlock();
    return descriptor;
}

int kernel_edge_iommufd_descriptor_retain(edge_iommufd_handle_t handle) {
    edge_iommufd_context_t *context;
    int status;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status == 0) {
        if (context->references == UINT32_MAX)
            status = -EDGE_LINUX_EOVERFLOW;
        else
            ++context->references;
    }
    iommufd_unlock();
    return status;
}

int kernel_edge_iommufd_descriptor_release(edge_iommufd_handle_t handle) {
    edge_iommufd_context_t *context;
    int status;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status == 0) {
        if (context->references == 0) {
            status = -EDGE_LINUX_EBADF;
        } else if (--context->references == 0) {
            context_clear(context);
            context->live = 0;
        }
    }
    iommufd_unlock();
    return status;
}

int kernel_edge_iommufd_descriptor_acquire(int32_t descriptor,
                                           edge_iommufd_handle_t *handle) {
    edge_iommufd_context_t *context;
    int status;
    if (!g_descriptors || !handle) return -EDGE_LINUX_EINVAL;
    status = g_descriptors->resolve(g_descriptor_context, descriptor, handle);
    if (status < 0) return -EDGE_LINUX_EBADF;
    iommufd_lock();
    status = context_resolve(*handle, &context);
    if (status == 0) {
        if (context->references == UINT32_MAX)
            status = -EDGE_LINUX_EOVERFLOW;
        else
            ++context->references;
    }
    iommufd_unlock();
    return status;
}

int kernel_edge_iommufd_ioas_exists(edge_iommufd_handle_t handle,
                                    uint32_t ioas_id) {
    edge_iommufd_context_t *context;
    int status;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status == 0 && !ioas_find(context, ioas_id))
        status = -EDGE_LINUX_ENOENT;
    iommufd_unlock();
    return status;
}

static int device_exists(const edge_iommufd_context_t *context,
                         uint32_t dev_id) {
    if (dev_id == 0) return 0;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_DEVICES; ++index) {
        if (context->devices[index] == dev_id) return 1;
    }
    return 0;
}

int kernel_edge_iommufd_device_register(edge_iommufd_handle_t handle,
                                        uint32_t dev_id) {
    edge_iommufd_context_t *context;
    int status;
    if (dev_id == 0) return -EDGE_LINUX_EINVAL;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status < 0) goto out;
    if (device_exists(context, dev_id)) {
        status = -EDGE_LINUX_EEXIST;
        goto out;
    }
    status = -EDGE_LINUX_ENOSPC;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_DEVICES; ++index) {
        if (context->devices[index] != 0) continue;
        context->devices[index] = dev_id;
        status = 0;
        break;
    }
out:
    iommufd_unlock();
    return status;
}

int kernel_edge_iommufd_device_unregister(edge_iommufd_handle_t handle,
                                          uint32_t dev_id) {
    edge_iommufd_context_t *context;
    int status;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status < 0) goto out;
    status = -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_DEVICES; ++index) {
        if (context->devices[index] != dev_id) continue;
        context->devices[index] = 0;
        status = 0;
        break;
    }
out:
    iommufd_unlock();
    return status;
}

static uint32_t hwpt_ioas(edge_iommufd_context_t *context, uint32_t pt_id,
                          uint32_t *hwpt_index) {
    if (ioas_find(context, pt_id)) return pt_id;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_HWPTS; ++index) {
        if (!context->hwpts[index].live || context->hwpts[index].id != pt_id)
            continue;
        if (hwpt_index) *hwpt_index = index;
        return context->hwpts[index].ioas_id;
    }
    return 0;
}

int kernel_edge_iommufd_pt_retain(edge_iommufd_handle_t handle,
                                  uint32_t pt_id, uint32_t *ioas_id) {
    edge_iommufd_context_t *context;
    uint32_t hwpt_index = UINT32_MAX;
    uint32_t resolved;
    int status;
    if (!ioas_id) return -EDGE_LINUX_EINVAL;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status < 0) goto out;
    resolved = hwpt_ioas(context, pt_id, &hwpt_index);
    if (resolved == 0) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (hwpt_index != UINT32_MAX) {
        if (context->hwpts[hwpt_index].references == UINT16_MAX) {
            status = -EDGE_LINUX_EOVERFLOW;
            goto out;
        }
        ++context->hwpts[hwpt_index].references;
    }
    *ioas_id = resolved;
    status = 0;
out:
    iommufd_unlock();
    return status;
}

int kernel_edge_iommufd_pt_release(edge_iommufd_handle_t handle,
                                   uint32_t pt_id) {
    edge_iommufd_context_t *context;
    int status;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status < 0) goto out;
    status = -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_HWPTS; ++index) {
        if (!context->hwpts[index].live || context->hwpts[index].id != pt_id)
            continue;
        if (context->hwpts[index].references == 0)
            status = -EDGE_LINUX_EINVAL;
        else {
            --context->hwpts[index].references;
            status = 0;
        }
        break;
    }
out:
    iommufd_unlock();
    return status;
}

int kernel_edge_iommufd_ioas_attach(
        edge_iommufd_handle_t handle, uint32_t ioas_id,
        const kernel_edge_iommufd_ioas_ops_t *ops, void *callback_context,
        uint32_t *attachment_id) {
    edge_iommufd_context_t *context;
    edge_iommufd_attachment_t *attachment = 0;
    int status;

    if (!ops || !ops->map || !ops->unmap || !attachment_id)
        return -EDGE_LINUX_EINVAL;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status < 0) goto out;
    if (!ioas_find(context, ioas_id)) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_ATTACHMENTS; ++index) {
        if (!g_attachments[index].live && !attachment)
            attachment = &g_attachments[index];
        if (g_attachments[index].live &&
            handle_equal(g_attachments[index].owner, handle) &&
            g_attachments[index].ioas_id == ioas_id &&
            g_attachments[index].context == callback_context) {
            status = -EDGE_LINUX_EBUSY;
            goto out;
        }
    }
    if (!attachment) {
        status = -EDGE_LINUX_ENOSPC;
        goto out;
    }
    if (g_next_attachment_id == 0) {
        status = -EDGE_LINUX_EOVERFLOW;
        goto out;
    }
    attachment->live = 1;
    attachment->id = g_next_attachment_id++;
    attachment->ioas_id = ioas_id;
    attachment->owner = handle;
    attachment->ops = *ops;
    attachment->context = callback_context;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        edge_iommufd_mapping_t *map = &context->maps[index];
        if (!map->live || map->ioas_id != ioas_id) continue;
        status = ops->map(callback_context, map->iova, map->user_va,
                          map->length, map->flags);
        if (status < 0) {
            for (uint32_t rollback = 0; rollback < index; ++rollback) {
                edge_iommufd_mapping_t *prior = &context->maps[rollback];
                if (prior->live && prior->ioas_id == ioas_id)
                    (void)ops->unmap(callback_context, prior->iova,
                                     prior->length);
            }
            attachment->live = 0;
            goto out;
        }
    }
    *attachment_id = attachment->id;
    status = 0;
out:
    iommufd_unlock();
    return status;
}

int kernel_edge_iommufd_ioas_detach(edge_iommufd_handle_t handle,
                                    uint32_t attachment_id) {
    edge_iommufd_context_t *context;
    edge_iommufd_attachment_t *attachment = 0;
    int status;

    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status < 0) goto out;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_ATTACHMENTS; ++index) {
        if (g_attachments[index].live &&
            g_attachments[index].id == attachment_id &&
            handle_equal(g_attachments[index].owner, handle)) {
            attachment = &g_attachments[index];
            break;
        }
    }
    if (!attachment) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        edge_iommufd_mapping_t *map = &context->maps[index];
        if (!map->live || map->ioas_id != attachment->ioas_id) continue;
        status = attachment->ops.unmap(
            attachment->context, map->iova, map->length);
        if (status < 0) {
            for (uint32_t rollback = 0; rollback < index; ++rollback) {
                edge_iommufd_mapping_t *prior = &context->maps[rollback];
                if (prior->live && prior->ioas_id == attachment->ioas_id)
                    (void)attachment->ops.map(attachment->context,
                        prior->iova, prior->user_va, prior->length,
                        prior->flags);
            }
            goto out;
        }
    }
    attachment->live = 0;
    status = 0;
out:
    iommufd_unlock();
    return status;
}

static int copy_from(const kernel_ioctl_request_t *request, void *destination,
                     uint64_t size) {
    if (!request->argument || !request->copy_from_user ||
        request->copy_from_user(request->copy_context, destination,
                                request->argument, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int copy_to(const kernel_ioctl_request_t *request, const void *source,
                   uint64_t size) {
    if (!request->argument || !request->copy_to_user ||
        request->copy_to_user(request->copy_context, request->argument,
                              source, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static edge_iommufd_ioas_t *ioas_find(edge_iommufd_context_t *context,
                                      uint32_t id) {
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_IOAS; ++index) {
        if (context->ioas[index].live && context->ioas[index].id == id)
            return &context->ioas[index];
    }
    return 0;
}

static int ioas_alloc(const kernel_ioctl_request_t *request,
                      edge_iommufd_context_t *context) {
    edge_iommu_ioas_alloc_t allocation;
    int status = copy_from(request, &allocation, sizeof(allocation));
    if (status < 0) return status;
    if (allocation.size < sizeof(allocation) || allocation.flags != 0)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_IOAS; ++index) {
        edge_iommufd_ioas_t *ioas = &context->ioas[index];
        if (ioas->live) continue;
        if (context->next_id == 0) return -EDGE_LINUX_EOVERFLOW;
        ioas->live = 1;
        ioas->huge_pages = 1;
        ioas->allowed_count = 0;
        ioas->id = context->next_id++;
        allocation.out_ioas_id = ioas->id;
        status = copy_to(request, &allocation, sizeof(allocation));
        if (status < 0) ioas->live = 0;
        return status;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int object_destroy(const kernel_ioctl_request_t *request,
                          edge_iommufd_handle_t owner,
                          edge_iommufd_context_t *context) {
    edge_iommu_destroy_t destroy;
    edge_iommufd_ioas_t *ioas;
    int status = copy_from(request, &destroy, sizeof(destroy));
    if (status < 0) return status;
    if (destroy.size < sizeof(destroy)) return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_HWPTS; ++index) {
        if (!context->hwpts[index].live ||
            context->hwpts[index].id != destroy.id)
            continue;
        if (context->hwpts[index].references != 0)
            return -EDGE_LINUX_EBUSY;
        context->hwpts[index].live = 0;
        return 0;
    }
    ioas = ioas_find(context, destroy.id);
    if (!ioas) return -EDGE_LINUX_ENOENT;
    if (context->vfio_ioas_id == destroy.id) return -EDGE_LINUX_EBUSY;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_ATTACHMENTS; ++index) {
        if (g_attachments[index].live &&
            handle_equal(g_attachments[index].owner, owner) &&
            g_attachments[index].ioas_id == destroy.id)
            return -EDGE_LINUX_EBUSY;
    }
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (context->maps[index].live &&
            context->maps[index].ioas_id == destroy.id)
            return -EDGE_LINUX_EBUSY;
    }
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_HWPTS; ++index) {
        if (context->hwpts[index].live &&
            context->hwpts[index].ioas_id == destroy.id)
            return -EDGE_LINUX_EBUSY;
    }
    ioas->live = 0;
    return 0;
}

static int map_range_allowed(const edge_iommufd_ioas_t *ioas,
                             uint64_t iova, uint64_t length) {
    uint64_t last;
    if (length == 0 || iova > UINT64_MAX - (length - 1u)) return 0;
    last = iova + length - 1u;
    if (ioas->allowed_count == 0)
        return iova >= EDGE_IOMMUFD_PAGE_SIZE &&
            last <= UINT64_MAX - EDGE_IOMMUFD_PAGE_SIZE;
    for (uint32_t index = 0; index < ioas->allowed_count; ++index) {
        if (iova >= ioas->allowed[index].start &&
            last <= ioas->allowed[index].last)
            return 1;
    }
    return 0;
}

static int map_range_free(const edge_iommufd_context_t *context,
                          uint32_t ioas_id, uint64_t iova, uint64_t length) {
    uint64_t end = iova + length;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        const edge_iommufd_mapping_t *map = &context->maps[index];
        if (!map->live || map->ioas_id != ioas_id) continue;
        if (iova < map->iova + map->length && map->iova < end) return 0;
    }
    return 1;
}

static int map_insert(edge_iommufd_context_t *context,
                      edge_iommufd_ioas_t *ioas, uint32_t flags,
                      uint64_t user_va, uint64_t length, uint64_t *iova,
                      uint8_t file_backed, uint64_t file_cookie) {
    uint64_t candidate = *iova;
    if ((flags & EDGE_IOMMU_IOAS_MAP_FIXED_IOVA) == 0) {
        candidate = ioas->allowed_count == 0 ? EDGE_IOMMUFD_PAGE_SIZE :
            ioas->allowed[0].start;
        while (map_range_allowed(ioas, candidate, length) &&
               !map_range_free(context, ioas->id, candidate, length)) {
            uint64_t next = candidate + EDGE_IOMMUFD_PAGE_SIZE;
            if (next < candidate) return -EDGE_LINUX_ENOSPC;
            candidate = next;
        }
    }
    if ((candidate & (EDGE_IOMMUFD_PAGE_SIZE - 1u)) != 0 ||
        (user_va & (EDGE_IOMMUFD_PAGE_SIZE - 1u)) != 0 ||
        (length & (EDGE_IOMMUFD_PAGE_SIZE - 1u)) != 0 ||
        !map_range_allowed(ioas, candidate, length))
        return -EDGE_LINUX_EINVAL;
    if (!map_range_free(context, ioas->id, candidate, length))
        return -EDGE_LINUX_EEXIST;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        edge_iommufd_mapping_t *map = &context->maps[index];
        if (map->live) continue;
        map->live = 1;
        map->flags = flags;
        map->ioas_id = ioas->id;
        map->user_va = user_va;
        map->iova = candidate;
        map->length = length;
        map->file_backed = file_backed;
        map->file_cookie = file_cookie;
        *iova = candidate;
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int ioas_map(const kernel_ioctl_request_t *request,
                    edge_iommufd_handle_t owner,
                    edge_iommufd_context_t *context) {
    edge_iommu_ioas_map_t map;
    edge_iommufd_ioas_t *ioas;
    int status = copy_from(request, &map, sizeof(map));
    if (status < 0) return status;
    if (map.size < sizeof(map) || map.reserved != 0 ||
        (map.flags & ~EDGE_IOMMU_IOAS_MAP_VALID_FLAGS) != 0 ||
        (map.flags & (EDGE_IOMMU_IOAS_MAP_READABLE |
                      EDGE_IOMMU_IOAS_MAP_WRITEABLE)) == 0)
        return -EDGE_LINUX_EINVAL;
    ioas = ioas_find(context, map.ioas_id);
    if (!ioas) return -EDGE_LINUX_ENOENT;
    status = map_insert(context, ioas, map.flags, map.user_va,
                        map.length, &map.iova, 0, 0);
    if (status < 0) return status;
    edge_iommufd_mapping_t *inserted = 0;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (context->maps[index].live &&
            context->maps[index].ioas_id == map.ioas_id &&
            context->maps[index].iova == map.iova &&
            context->maps[index].length == map.length) {
            inserted = &context->maps[index];
            break;
        }
    }
    if (!inserted) return -EDGE_LINUX_EIO;
    status = mapping_notify_map(owner, inserted);
    if (status < 0) {
        inserted->live = 0;
        return status;
    }
    status = copy_to(request, &map, sizeof(map));
    if (status < 0) {
        (void)mapping_notify_unmap(owner, inserted);
        inserted->live = 0;
    }
    return status;
}

static int ioas_map_file(const kernel_ioctl_request_t *request,
                         edge_iommufd_handle_t owner,
                         edge_iommufd_context_t *context) {
    edge_iommu_ioas_map_file_t map;
    edge_iommufd_mapping_t *inserted = 0;
    edge_iommufd_ioas_t *ioas;
    uint64_t user_va;
    uint64_t cookie;
    int status = copy_from(request, &map, sizeof(map));
    if (status < 0) return status;
    if (map.size < sizeof(map) || map.fd < 0 ||
        (map.flags & ~EDGE_IOMMU_IOAS_MAP_VALID_FLAGS) != 0 ||
        (map.flags & (EDGE_IOMMU_IOAS_MAP_READABLE |
                      EDGE_IOMMU_IOAS_MAP_WRITEABLE)) == 0 ||
        map.length == 0 || map.start > UINT64_MAX - map.length)
        return -EDGE_LINUX_EINVAL;
    ioas = ioas_find(context, map.ioas_id);
    if (!ioas) return -EDGE_LINUX_ENOENT;
    if (!g_files) return -EDGE_LINUX_EOPNOTSUPP;
    status = g_files->acquire(g_file_context, map.fd, map.start,
                              map.length, &user_va, &cookie);
    if (status < 0) return status;
    status = map_insert(context, ioas, map.flags, user_va, map.length,
                        &map.iova, 1, cookie);
    if (status < 0) {
        g_files->release(g_file_context, cookie);
        return status;
    }
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (context->maps[index].live &&
            context->maps[index].ioas_id == map.ioas_id &&
            context->maps[index].iova == map.iova &&
            context->maps[index].length == map.length) {
            inserted = &context->maps[index];
            break;
        }
    }
    if (!inserted) {
        g_files->release(g_file_context, cookie);
        return -EDGE_LINUX_EIO;
    }
    status = mapping_notify_map(owner, inserted);
    if (status < 0) {
        inserted->live = 0;
        g_files->release(g_file_context, cookie);
        return status;
    }
    status = copy_to(request, &map, sizeof(map));
    if (status < 0) {
        (void)mapping_notify_unmap(owner, inserted);
        inserted->live = 0;
        g_files->release(g_file_context, cookie);
    }
    return status;
}

static int ioas_change_process(const kernel_ioctl_request_t *request,
                               edge_iommufd_context_t *context) {
    edge_iommu_ioas_change_process_t change;
    uint32_t cookie_count = 0;
    int status = copy_from(request, &change, sizeof(change));
    if (status < 0) return status;
    if (change.size < sizeof(change) || change.reserved != 0)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (!context->maps[index].live) continue;
        if (!context->maps[index].file_backed)
            return -EDGE_LINUX_EINVAL;
        g_file_cookie_scratch[cookie_count++] =
            context->maps[index].file_cookie;
    }
    /*
     * Changing ownership before any DMA map exists is a successful no-op.
     * QEMU uses this exact operation to detect whether a newly opened
     * IOMMUFD understands process transfer.  A file backend is needed only
     * when there are file-backed mappings whose pin accounting must move.
     */
    if (cookie_count == 0) return 0;
    if (!g_files) return -EDGE_LINUX_EOPNOTSUPP;
    return g_files->change_process(g_file_context, g_file_cookie_scratch,
                                   cookie_count);
}

static int ioas_copy(const kernel_ioctl_request_t *request,
                     edge_iommufd_handle_t owner,
                     edge_iommufd_context_t *context) {
    edge_iommu_ioas_copy_t copy;
    edge_iommufd_mapping_t *source = 0;
    edge_iommufd_ioas_t *destination;
    uint64_t destination_iova;
    int status = copy_from(request, &copy, sizeof(copy));
    if (status < 0) return status;
    if (copy.size < sizeof(copy) ||
        (copy.flags & ~EDGE_IOMMU_IOAS_MAP_VALID_FLAGS) != 0)
        return -EDGE_LINUX_EINVAL;
    destination = ioas_find(context, copy.dst_ioas_id);
    if (!destination || !ioas_find(context, copy.src_ioas_id))
        return -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        edge_iommufd_mapping_t *map = &context->maps[index];
        if (map->live && map->ioas_id == copy.src_ioas_id &&
            map->iova == copy.src_iova && map->length == copy.length) {
            source = map;
            break;
        }
    }
    if (!source) return -EDGE_LINUX_ENOENT;
    destination_iova = copy.dst_iova;
    if (source->file_backed) {
        if (!g_files) return -EDGE_LINUX_EOPNOTSUPP;
        status = g_files->retain(g_file_context, source->file_cookie);
        if (status < 0) return status;
    }
    status = map_insert(context, destination, copy.flags,
                        source->user_va, copy.length, &destination_iova,
                        source->file_backed, source->file_cookie);
    if (status < 0 && source->file_backed)
        g_files->release(g_file_context, source->file_cookie);
    if (status < 0) return status;
    copy.dst_iova = destination_iova;
    edge_iommufd_mapping_t *inserted = 0;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (context->maps[index].live &&
            context->maps[index].ioas_id == copy.dst_ioas_id &&
            context->maps[index].iova == copy.dst_iova &&
            context->maps[index].length == copy.length) {
            inserted = &context->maps[index];
            break;
        }
    }
    if (!inserted) {
        if (source->file_backed)
            g_files->release(g_file_context, source->file_cookie);
        return -EDGE_LINUX_EIO;
    }
    status = mapping_notify_map(owner, inserted);
    if (status < 0) {
        inserted->live = 0;
        if (inserted->file_backed)
            g_files->release(g_file_context, inserted->file_cookie);
        return status;
    }
    status = copy_to(request, &copy, sizeof(copy));
    if (status < 0) {
        (void)mapping_notify_unmap(owner, inserted);
        inserted->live = 0;
        if (inserted->file_backed)
            g_files->release(g_file_context, inserted->file_cookie);
    }
    return status;
}

static int ioas_unmap(const kernel_ioctl_request_t *request,
                      edge_iommufd_handle_t owner,
                      edge_iommufd_context_t *context) {
    edge_iommu_ioas_unmap_t unmap;
    uint64_t end;
    uint64_t unmapped = 0;
    int status = copy_from(request, &unmap, sizeof(unmap));
    if (status < 0) return status;
    if (unmap.size < sizeof(unmap)) return -EDGE_LINUX_EINVAL;
    if (!ioas_find(context, unmap.ioas_id)) return -EDGE_LINUX_ENOENT;
    if (unmap.iova == 0 && unmap.length == UINT64_MAX) {
        end = UINT64_MAX;
    } else {
        if (unmap.length == 0 || unmap.iova > UINT64_MAX - unmap.length)
            return -EDGE_LINUX_EINVAL;
        end = unmap.iova + unmap.length;
    }
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        edge_iommufd_mapping_t *map = &context->maps[index];
        g_unmap_scratch[index] = 0;
        if (!map->live || map->ioas_id != unmap.ioas_id) continue;
        if (map->iova >= unmap.iova && map->iova + map->length <= end) {
            unmapped += map->length;
            g_unmap_scratch[index] = 1;
        }
    }
    if (unmapped == 0) return -EDGE_LINUX_ENOENT;
    unmap.length = unmapped;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (!g_unmap_scratch[index]) continue;
        status = mapping_notify_unmap(owner, &context->maps[index]);
        if (status < 0) {
            for (uint32_t rollback = 0; rollback < index; ++rollback) {
                if (g_unmap_scratch[rollback] == 2)
                    (void)mapping_notify_map(owner,
                        &context->maps[rollback]);
            }
            return status;
        }
        g_unmap_scratch[index] = 2;
    }
    status = copy_to(request, &unmap, sizeof(unmap));
    if (status < 0) {
        for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
            if (g_unmap_scratch[index] == 2)
                (void)mapping_notify_map(owner, &context->maps[index]);
        }
        return status;
    }
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        if (g_unmap_scratch[index]) {
            if (context->maps[index].file_backed && g_files)
                g_files->release(g_file_context,
                                 context->maps[index].file_cookie);
            context->maps[index].live = 0;
        }
    }
    return 0;
}

static int ioas_ranges(const kernel_ioctl_request_t *request,
                       edge_iommufd_context_t *context) {
    edge_iommu_ioas_iova_ranges_t ranges;
    edge_iommufd_ioas_t *ioas;
    edge_iommu_iova_range_t default_range = {
        .start = EDGE_IOMMUFD_PAGE_SIZE,
        .last = UINT64_MAX - EDGE_IOMMUFD_PAGE_SIZE,
    };
    uint32_t capacity;
    uint32_t required;
    int status = copy_from(request, &ranges, sizeof(ranges));
    if (status < 0) return status;
    if (ranges.size < sizeof(ranges) || ranges.reserved != 0)
        return -EDGE_LINUX_EINVAL;
    ioas = ioas_find(context, ranges.ioas_id);
    if (!ioas) return -EDGE_LINUX_ENOENT;
    capacity = ranges.num_iovas;
    required = ioas->allowed_count == 0 ? 1u : ioas->allowed_count;
    if (capacity >= required) {
        if (!ranges.allowed_iovas || !request->copy_to_user)
            return -EDGE_LINUX_EFAULT;
        for (uint32_t index = 0; index < required; ++index) {
            const edge_iommu_iova_range_t *range = ioas->allowed_count == 0 ?
                &default_range : &ioas->allowed[index];
            if (request->copy_to_user(request->copy_context,
                    ranges.allowed_iovas + index * sizeof(*range),
                    range, sizeof(*range)) < 0)
                return -EDGE_LINUX_EFAULT;
        }
    }
    ranges.num_iovas = required;
    ranges.out_iova_alignment = EDGE_IOMMUFD_PAGE_SIZE;
    status = copy_to(request, &ranges, sizeof(ranges));
    if (status < 0) return status;
    return capacity < required ? -EDGE_LINUX_EMSGSIZE : 0;
}

static int ioas_allow(const kernel_ioctl_request_t *request,
                      edge_iommufd_context_t *context) {
    edge_iommu_ioas_allow_iovas_t allow;
    edge_iommu_iova_range_t ranges[EDGE_IOMMUFD_MAX_ALLOWED_RANGES];
    edge_iommufd_ioas_t *ioas;
    int status = copy_from(request, &allow, sizeof(allow));
    if (status < 0) return status;
    if (allow.size < sizeof(allow) || allow.reserved != 0 ||
        allow.num_iovas > EDGE_IOMMUFD_MAX_ALLOWED_RANGES)
        return -EDGE_LINUX_EINVAL;
    ioas = ioas_find(context, allow.ioas_id);
    if (!ioas) return -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0; index < allow.num_iovas; ++index) {
        edge_iommu_iova_range_t range;
        if (!allow.allowed_iovas || !request->copy_from_user ||
            request->copy_from_user(request->copy_context, &range,
                allow.allowed_iovas + index * sizeof(range),
                sizeof(range)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (range.start > range.last || range.last == UINT64_MAX ||
            (range.start & (EDGE_IOMMUFD_PAGE_SIZE - 1u)) != 0 ||
            ((range.last + 1u) & (EDGE_IOMMUFD_PAGE_SIZE - 1u)) != 0)
            return -EDGE_LINUX_EINVAL;
        ranges[index] = range;
    }
    for (uint32_t index = 0; index < allow.num_iovas; ++index)
        ioas->allowed[index] = ranges[index];
    ioas->allowed_count = (uint16_t)allow.num_iovas;
    return 0;
}

static int option_execute(const kernel_ioctl_request_t *request,
                          edge_iommufd_context_t *context) {
    edge_iommu_option_t option;
    edge_iommufd_ioas_t *ioas = 0;
    int status = copy_from(request, &option, sizeof(option));
    if (status < 0) return status;
    if (option.size < sizeof(option) || option.reserved != 0 ||
        option.op > EDGE_IOMMU_OPTION_OP_GET || option.value > 1)
        return -EDGE_LINUX_EINVAL;
    if (option.option_id == EDGE_IOMMU_OPTION_RLIMIT_MODE) {
        if (option.object_id != 0) return -EDGE_LINUX_EINVAL;
        if (option.op == EDGE_IOMMU_OPTION_OP_SET)
            context->rlimit_mode = (uint8_t)option.value;
        else
            option.value = context->rlimit_mode;
    } else if (option.option_id == EDGE_IOMMU_OPTION_HUGE_PAGES) {
        ioas = ioas_find(context, option.object_id);
        if (!ioas) return -EDGE_LINUX_ENOENT;
        if (option.op == EDGE_IOMMU_OPTION_OP_SET)
            ioas->huge_pages = (uint8_t)option.value;
        else
            option.value = ioas->huge_pages;
    } else {
        return -EDGE_LINUX_EOPNOTSUPP;
    }
    return option.op == EDGE_IOMMU_OPTION_OP_GET ?
        copy_to(request, &option, sizeof(option)) : 0;
}

static int vfio_ioas_execute(const kernel_ioctl_request_t *request,
                             edge_iommufd_context_t *context) {
    edge_iommu_vfio_ioas_t vfio_ioas;
    int status = copy_from(request, &vfio_ioas, sizeof(vfio_ioas));
    if (status < 0) return status;
    if (vfio_ioas.size < sizeof(vfio_ioas) || vfio_ioas.reserved != 0 ||
        vfio_ioas.op > EDGE_IOMMU_VFIO_IOAS_CLEAR)
        return -EDGE_LINUX_EINVAL;
    if (vfio_ioas.op == EDGE_IOMMU_VFIO_IOAS_SET) {
        if (!ioas_find(context, vfio_ioas.ioas_id))
            return -EDGE_LINUX_ENOENT;
        context->vfio_ioas_id = vfio_ioas.ioas_id;
        return 0;
    }
    if (vfio_ioas.op == EDGE_IOMMU_VFIO_IOAS_CLEAR) {
        if (vfio_ioas.ioas_id != 0) return -EDGE_LINUX_EINVAL;
        context->vfio_ioas_id = 0;
        return 0;
    }
    if (vfio_ioas.ioas_id != 0) return -EDGE_LINUX_EINVAL;
    if (context->vfio_ioas_id == 0) return -EDGE_LINUX_ENOENT;
    vfio_ioas.ioas_id = context->vfio_ioas_id;
    return copy_to(request, &vfio_ioas, sizeof(vfio_ioas));
}

static int hwpt_alloc_execute(const kernel_ioctl_request_t *request,
                              edge_iommufd_context_t *context) {
    edge_iommu_hwpt_alloc_t allocation;
    uint32_t valid_flags = EDGE_IOMMU_HWPT_ALLOC_NEST_PARENT |
        EDGE_IOMMU_HWPT_ALLOC_DIRTY_TRACKING |
        EDGE_IOMMU_HWPT_FAULT_ID_VALID | EDGE_IOMMU_HWPT_ALLOC_PASID;
    int status = copy_from(request, &allocation, sizeof(allocation));
    if (status < 0) return status;
    if (allocation.size < sizeof(allocation) || allocation.reserved != 0 ||
        allocation.reserved2 != 0 || (allocation.flags & ~valid_flags) != 0)
        return -EDGE_LINUX_EINVAL;
    if (!device_exists(context, allocation.dev_id) ||
        !ioas_find(context, allocation.pt_id))
        return -EDGE_LINUX_ENOENT;
    if ((allocation.flags & (EDGE_IOMMU_HWPT_FAULT_ID_VALID |
                             EDGE_IOMMU_HWPT_ALLOC_PASID)) != 0 ||
        allocation.data_type != EDGE_IOMMU_HWPT_DATA_NONE ||
        allocation.data_len != 0 || allocation.data_uptr != 0 ||
        allocation.fault_id != 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_HWPTS; ++index) {
        if (context->hwpts[index].live) continue;
        if (context->next_id == 0) return -EDGE_LINUX_EOVERFLOW;
        context->hwpts[index].live = 1;
        context->hwpts[index].dirty_enabled =
            (allocation.flags & EDGE_IOMMU_HWPT_ALLOC_DIRTY_TRACKING) != 0;
        context->hwpts[index].references = 0;
        context->hwpts[index].id = context->next_id++;
        context->hwpts[index].dev_id = allocation.dev_id;
        context->hwpts[index].ioas_id = allocation.pt_id;
        context->hwpts[index].flags = allocation.flags;
        allocation.out_hwpt_id = context->hwpts[index].id;
        status = copy_to(request, &allocation, sizeof(allocation));
        if (status < 0) context->hwpts[index].live = 0;
        return status;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int hw_info_execute(const kernel_ioctl_request_t *request,
                           edge_iommufd_context_t *context) {
    edge_iommu_hw_info_t info;
    int status = copy_from(request, &info, sizeof(info));
    if (status < 0) return status;
    if (info.size < sizeof(info) ||
        (info.flags & ~EDGE_IOMMU_HW_INFO_FLAG_INPUT_TYPE) != 0 ||
        info.reserved[0] != 0 || info.reserved[1] != 0 ||
        info.reserved[2] != 0)
        return -EDGE_LINUX_EINVAL;
    if (!device_exists(context, info.dev_id)) return -EDGE_LINUX_ENOENT;
    if ((info.flags & EDGE_IOMMU_HW_INFO_FLAG_INPUT_TYPE) != 0 &&
        info.data_type != 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    info.data_len = 0;
    info.data_type = 0;
    info.out_max_pasid_log2 = 0;
    info.out_capabilities = EDGE_IOMMU_HW_CAP_DIRTY_TRACKING;
    return copy_to(request, &info, sizeof(info));
}

static int hwpt_find_index(edge_iommufd_context_t *context,
                           uint32_t hwpt_id, uint32_t *index_out) {
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_HWPTS; ++index) {
        if (context->hwpts[index].live &&
            context->hwpts[index].id == hwpt_id) {
            *index_out = index;
            return 0;
        }
    }
    return -EDGE_LINUX_ENOENT;
}

static int hwpt_dirty_tracking_execute(
        const kernel_ioctl_request_t *request,
        edge_iommufd_context_t *context) {
    edge_iommu_hwpt_set_dirty_tracking_t dirty;
    uint32_t index;
    int status = copy_from(request, &dirty, sizeof(dirty));
    if (status < 0) return status;
    if (dirty.size < sizeof(dirty) || dirty.reserved != 0 ||
        (dirty.flags & ~EDGE_IOMMU_HWPT_DIRTY_TRACKING_ENABLE) != 0)
        return -EDGE_LINUX_EINVAL;
    status = hwpt_find_index(context, dirty.hwpt_id, &index);
    if (status < 0) return status;
    context->hwpts[index].dirty_enabled =
        (dirty.flags & EDGE_IOMMU_HWPT_DIRTY_TRACKING_ENABLE) != 0;
    return 0;
}

static int page_is_mapped(const edge_iommufd_context_t *context,
                          uint32_t ioas_id, uint64_t iova,
                          uint64_t page_size) {
    uint64_t end = iova + page_size;
    for (uint32_t index = 0; index < EDGE_IOMMUFD_MAX_MAPS; ++index) {
        const edge_iommufd_mapping_t *map = &context->maps[index];
        if (map->live && map->ioas_id == ioas_id &&
            iova < map->iova + map->length && map->iova < end)
            return 1;
    }
    return 0;
}

static int hwpt_dirty_bitmap_execute(const kernel_ioctl_request_t *request,
                                     edge_iommufd_context_t *context) {
    edge_iommu_hwpt_get_dirty_bitmap_t bitmap;
    uint64_t pages;
    uint64_t words;
    uint32_t hwpt_index;
    int status = copy_from(request, &bitmap, sizeof(bitmap));
    if (status < 0) return status;
    if (bitmap.size < sizeof(bitmap) || bitmap.reserved != 0 ||
        (bitmap.flags & ~EDGE_IOMMU_HWPT_GET_DIRTY_BITMAP_NO_CLEAR) != 0 ||
        bitmap.page_size == 0 ||
        (bitmap.page_size & (bitmap.page_size - 1u)) != 0 ||
        bitmap.length == 0 || bitmap.length % bitmap.page_size != 0 ||
        bitmap.iova % bitmap.page_size != 0 || !bitmap.data ||
        bitmap.iova > UINT64_MAX - bitmap.length)
        return -EDGE_LINUX_EINVAL;
    status = hwpt_find_index(context, bitmap.hwpt_id, &hwpt_index);
    if (status < 0) return status;
    if (!context->hwpts[hwpt_index].dirty_enabled)
        return -EDGE_LINUX_EINVAL;
    pages = bitmap.length / bitmap.page_size;
    words = (pages + 63u) / 64u;
    for (uint64_t word_index = 0; word_index < words; ++word_index) {
        uint64_t word = 0;
        for (uint32_t bit = 0; bit < 64; ++bit) {
            uint64_t page = word_index * 64u + bit;
            uint64_t page_iova;
            if (page >= pages) break;
            page_iova = bitmap.iova + page * bitmap.page_size;
            if (page_is_mapped(context, context->hwpts[hwpt_index].ioas_id,
                               page_iova, bitmap.page_size))
                word |= UINT64_C(1) << bit;
        }
        if (!request->copy_to_user ||
            request->copy_to_user(request->copy_context,
                bitmap.data + word_index * sizeof(word), &word,
                sizeof(word)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

static int hwpt_invalidate_execute(const kernel_ioctl_request_t *request,
                                   edge_iommufd_context_t *context) {
    edge_iommu_hwpt_invalidate_t invalidate;
    uint32_t hwpt_index;
    int status = copy_from(request, &invalidate, sizeof(invalidate));
    if (status < 0) return status;
    if (invalidate.size < sizeof(invalidate) || invalidate.reserved != 0 ||
        invalidate.data_type >
            EDGE_IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3 ||
        (invalidate.entry_num != 0 &&
         (invalidate.entry_len == 0 || invalidate.data_uptr == 0)))
        return -EDGE_LINUX_EINVAL;
    status = hwpt_find_index(context, invalidate.hwpt_id, &hwpt_index);
    if (status < 0) return status;
    (void)hwpt_index;
    return -EDGE_LINUX_EOPNOTSUPP;
}

static int fault_queue_alloc_execute(const kernel_ioctl_request_t *request) {
    edge_iommu_fault_alloc_t allocation;
    int status = copy_from(request, &allocation, sizeof(allocation));
    if (status < 0) return status;
    if (allocation.size < sizeof(allocation) || allocation.flags != 0)
        return -EDGE_LINUX_EINVAL;
    return -EDGE_LINUX_EOPNOTSUPP;
}

static int viommu_alloc_execute(const kernel_ioctl_request_t *request,
                                edge_iommufd_context_t *context) {
    edge_iommu_viommu_alloc_t allocation;
    uint32_t hwpt_index;
    int status = copy_from(request, &allocation, sizeof(allocation));
    if (status < 0) return status;
    if (allocation.size < sizeof(allocation) || allocation.flags != 0 ||
        allocation.reserved != 0 ||
        allocation.type > EDGE_IOMMU_VIOMMU_TYPE_TEGRA241_CMDQV ||
        (allocation.data_len == 0) != (allocation.data_uptr == 0))
        return -EDGE_LINUX_EINVAL;
    if (!device_exists(context, allocation.dev_id))
        return -EDGE_LINUX_ENOENT;
    status = hwpt_find_index(context, allocation.hwpt_id, &hwpt_index);
    if (status < 0) return status;
    if ((context->hwpts[hwpt_index].flags &
         EDGE_IOMMU_HWPT_ALLOC_NEST_PARENT) == 0)
        return -EDGE_LINUX_EINVAL;
    return -EDGE_LINUX_EOPNOTSUPP;
}

static int vdevice_alloc_execute(const kernel_ioctl_request_t *request,
                                 edge_iommufd_context_t *context) {
    edge_iommu_vdevice_alloc_t allocation;
    int status = copy_from(request, &allocation, sizeof(allocation));
    if (status < 0) return status;
    if (allocation.size < sizeof(allocation)) return -EDGE_LINUX_EINVAL;
    if (!device_exists(context, allocation.dev_id))
        return -EDGE_LINUX_ENOENT;
    return -EDGE_LINUX_EOPNOTSUPP;
}

static int veventq_alloc_execute(const kernel_ioctl_request_t *request) {
    edge_iommu_veventq_alloc_t allocation;
    int status = copy_from(request, &allocation, sizeof(allocation));
    if (status < 0) return status;
    if (allocation.size < sizeof(allocation) || allocation.flags != 0 ||
        allocation.reserved != 0 || allocation.veventq_depth == 0 ||
        allocation.type > EDGE_IOMMU_VEVENTQ_TYPE_TEGRA241_CMDQV)
        return -EDGE_LINUX_EINVAL;
    return -EDGE_LINUX_EOPNOTSUPP;
}

static int hw_queue_alloc_execute(const kernel_ioctl_request_t *request) {
    edge_iommu_hw_queue_alloc_t allocation;
    int status = copy_from(request, &allocation, sizeof(allocation));
    if (status < 0) return status;
    if (allocation.size < sizeof(allocation) || allocation.flags != 0 ||
        allocation.type > EDGE_IOMMU_HW_QUEUE_TYPE_TEGRA241_CMDQV ||
        allocation.length == 0 ||
        allocation.nesting_parent_iova > UINT64_MAX - allocation.length)
        return -EDGE_LINUX_EINVAL;
    return -EDGE_LINUX_EOPNOTSUPP;
}

int64_t kernel_edge_iommufd_ioctl(const kernel_ioctl_request_t *request) {
    edge_iommufd_context_t *context;
    edge_iommufd_handle_t handle;
    int64_t status;
    if (!request || !g_descriptors) return -EDGE_LINUX_ENOTTY;
    status = g_descriptors->resolve(
        g_descriptor_context, request->descriptor, &handle);
    if (status < 0) return -EDGE_LINUX_ENOTTY;
    iommufd_lock();
    status = context_resolve(handle, &context);
    if (status < 0) goto out;
    switch (request->command) {
    case EDGE_IOMMU_DESTROY:
        status = object_destroy(request, handle, context);
        break;
    case EDGE_IOMMU_IOAS_ALLOC:
        status = ioas_alloc(request, context);
        break;
    case EDGE_IOMMU_IOAS_ALLOW_IOVAS:
        status = ioas_allow(request, context);
        break;
    case EDGE_IOMMU_IOAS_COPY:
        status = ioas_copy(request, handle, context);
        break;
    case EDGE_IOMMU_IOAS_IOVA_RANGES:
        status = ioas_ranges(request, context);
        break;
    case EDGE_IOMMU_IOAS_MAP:
        status = ioas_map(request, handle, context);
        break;
    case EDGE_IOMMU_IOAS_MAP_FILE:
        status = ioas_map_file(request, handle, context);
        break;
    case EDGE_IOMMU_IOAS_UNMAP:
        status = ioas_unmap(request, handle, context);
        break;
    case EDGE_IOMMU_OPTION:
        status = option_execute(request, context);
        break;
    case EDGE_IOMMU_VFIO_IOAS:
        status = vfio_ioas_execute(request, context);
        break;
    case EDGE_IOMMU_HWPT_ALLOC:
        status = hwpt_alloc_execute(request, context);
        break;
    case EDGE_IOMMU_GET_HW_INFO:
        status = hw_info_execute(request, context);
        break;
    case EDGE_IOMMU_HWPT_SET_DIRTY_TRACKING:
        status = hwpt_dirty_tracking_execute(request, context);
        break;
    case EDGE_IOMMU_HWPT_GET_DIRTY_BITMAP:
        status = hwpt_dirty_bitmap_execute(request, context);
        break;
    case EDGE_IOMMU_HWPT_INVALIDATE:
        status = hwpt_invalidate_execute(request, context);
        break;
    case EDGE_IOMMU_FAULT_QUEUE_ALLOC:
        status = fault_queue_alloc_execute(request);
        break;
    case EDGE_IOMMU_VIOMMU_ALLOC:
        status = viommu_alloc_execute(request, context);
        break;
    case EDGE_IOMMU_VDEVICE_ALLOC:
        status = vdevice_alloc_execute(request, context);
        break;
    case EDGE_IOMMU_IOAS_CHANGE_PROCESS:
        status = ioas_change_process(request, context);
        break;
    case EDGE_IOMMU_VEVENTQ_ALLOC:
        status = veventq_alloc_execute(request);
        break;
    case EDGE_IOMMU_HW_QUEUE_ALLOC:
        status = hw_queue_alloc_execute(request);
        break;
    default:
        status = -EDGE_LINUX_ENOTTY;
        break;
    }
out:
    iommufd_unlock();
    return status;
}
