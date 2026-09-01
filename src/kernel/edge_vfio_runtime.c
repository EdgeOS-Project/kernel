/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS descriptor and usercopy boundary for the VFIO ABI. */

#include "kernel/edge_vfio_runtime.h"
#include "kernel/edge_iommufd_runtime.h"
#include "kernel/linux_errno.h"

#define EDGE_VFIO_IRQ_DATA_MAX 4096u

static edge_vfio_object_table_t g_objects;
static const kernel_edge_vfio_descriptor_backend_ops_t *g_descriptors;
static void *g_descriptor_context;
static volatile uint32_t g_lock;
static uint8_t g_irq_data[EDGE_VFIO_IRQ_DATA_MAX];
typedef struct edge_vfio_iommufd_binding {
    uint8_t active;
    uint8_t attached;
    uint8_t reserved[2];
    edge_vfio_handle_t device;
    edge_iommufd_handle_t iommufd;
    uint32_t devid;
    uint32_t pt_id;
    uint32_t ioas_id;
    uint32_t attachment_id;
    uint32_t padding;
    uint64_t device_cookie;
    uint64_t vm_cookie;
} edge_vfio_iommufd_binding_t;
static edge_vfio_iommufd_binding_t g_iommufd_bindings[EDGE_VFIO_MAX_DEVICES];
static uint32_t g_next_devid = 1u;

static void runtime_lock(void) {
    while (__atomic_exchange_n(&g_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void runtime_unlock(void) {
    __atomic_store_n(&g_lock, 0u, __ATOMIC_RELEASE);
}

int kernel_edge_vfio_descriptor_backend_register(
        const kernel_edge_vfio_descriptor_backend_ops_t *ops, void *context) {
    if (!ops || !ops->install || !ops->resolve ||
        !ops->resolve_eventfd || !ops->close)
        return -EDGE_LINUX_EINVAL;
    g_descriptors = ops;
    g_descriptor_context = context;
    return 0;
}

int kernel_edge_vfio_backend_register(const edge_vfio_backend_ops_t *backend) {
    int status;
    if (!backend || !g_descriptors) return -EDGE_LINUX_ENODEV;
    runtime_lock();
    status = edge_vfio_object_table_init(&g_objects, backend);
    runtime_unlock();
    return status;
}

static int resolve(int32_t descriptor, kernel_edge_vfio_file_t *file) {
    if (!g_descriptors || !file) return -EDGE_LINUX_ENODEV;
    return g_descriptors->resolve(g_descriptor_context, descriptor, file);
}

static int install(kernel_edge_vfio_file_kind_t kind,
                   edge_vfio_handle_t handle) {
    if (!g_descriptors) return -EDGE_LINUX_ENODEV;
    return g_descriptors->install(g_descriptor_context, kind, handle);
}

int kernel_edge_vfio_open_container(void) {
    edge_vfio_handle_t handle;
    int status;
    runtime_lock();
    status = edge_vfio_container_create(&g_objects, &handle);
    if (status == 0) {
        status = install(KERNEL_EDGE_VFIO_FILE_CONTAINER, handle);
        if (status < 0) (void)edge_vfio_container_release(&g_objects, handle);
    }
    runtime_unlock();
    return status;
}

int kernel_edge_vfio_open_group(uint32_t group_id) {
    edge_vfio_handle_t handle;
    int status;
    runtime_lock();
    status = edge_vfio_group_open(&g_objects, group_id, &handle);
    if (status == 0) {
        status = install(KERNEL_EDGE_VFIO_FILE_GROUP, handle);
        if (status < 0) (void)edge_vfio_group_release(&g_objects, handle);
    }
    runtime_unlock();
    return status;
}

int kernel_edge_vfio_open_cdev(uint32_t device_id) {
    edge_vfio_handle_t handle;
    int status;
    runtime_lock();
    status = edge_vfio_device_open_cdev(&g_objects, device_id, &handle);
    if (status == 0) {
        status = install(KERNEL_EDGE_VFIO_FILE_DEVICE, handle);
        if (status < 0) (void)edge_vfio_device_release(&g_objects, handle);
    }
    runtime_unlock();
    return status;
}

int kernel_edge_vfio_cdev_path_parse(const char *path, uint32_t *device_id) {
    const char prefix[] = EDGE_VFIO_CDEV_PATH_PREFIX;
    uint64_t value = 0;
    uint32_t index = 0;
    if (!path || !device_id) return 0;
    while (prefix[index] != '\0') {
        if (path[index] != prefix[index]) return 0;
        ++index;
    }
    if (path[index] == '\0') return 0;
    while (path[index] >= '0' && path[index] <= '9') {
        value = value * 10u + (uint32_t)(path[index] - '0');
        if (value > UINT16_MAX) return 0;
        ++index;
    }
    if (path[index] != '\0') return 0;
    *device_id = (uint32_t)value;
    return 1;
}

int kernel_edge_vfio_group_path_parse(const char *path, uint32_t *group_id) {
    const char prefix[] = EDGE_VFIO_GROUP_PATH_PREFIX;
    uint64_t value = 0;
    uint32_t index = 0;
    if (!path || !group_id) return 0;
    while (prefix[index] != '\0') {
        if (path[index] != prefix[index]) return 0;
        ++index;
    }
    if (path[index] == '\0' ||
        (path[index] == 'v' && path[index + 1] == 'f' &&
         path[index + 2] == 'i' && path[index + 3] == 'o' &&
         path[index + 4] == '\0'))
        return 0;
    while (path[index] >= '0' && path[index] <= '9') {
        value = value * 10u + (uint32_t)(path[index] - '0');
        if (value > UINT32_MAX) return 0;
        ++index;
    }
    if (path[index] != '\0') return 0;
    *group_id = (uint32_t)value;
    return 1;
}

static int container_ioctl(const kernel_ioctl_request_t *request,
                           edge_vfio_handle_t handle) {
    edge_vfio_iommu_type1_info_t info;
    edge_vfio_iommu_type1_dma_map_t map;
    edge_vfio_iommu_type1_dma_unmap_t unmap;
    int status;

    if (request->command == EDGE_VFIO_GET_API_VERSION)
        return EDGE_VFIO_API_VERSION;
    if (request->command == EDGE_VFIO_CHECK_EXTENSION)
        return request->argument == EDGE_VFIO_TYPE1_IOMMU ||
            request->argument == EDGE_VFIO_TYPE1_V2_IOMMU;
    if (request->command == EDGE_VFIO_SET_IOMMU)
        return edge_vfio_container_set_iommu(
            &g_objects, handle, (uint32_t)request->argument);
    if (request->command == EDGE_VFIO_IOMMU_ENABLE)
        return edge_vfio_container_set_enabled(&g_objects, handle, 1);
    if (request->command == EDGE_VFIO_IOMMU_DISABLE)
        return edge_vfio_container_set_enabled(&g_objects, handle, 0);
    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->command == EDGE_VFIO_IOMMU_GET_INFO) {
        if (!request->copy_to_user || request->copy_from_user(
                request->copy_context, &info, request->argument,
                sizeof(info)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (info.argsz < sizeof(info)) return -EDGE_LINUX_EINVAL;
        info.flags = 0;
        info.iova_pgsizes = EDGE_VFIO_PAGE_SIZE;
        return request->copy_to_user(request->copy_context,
            request->argument, &info, sizeof(info)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    if (request->command == EDGE_VFIO_IOMMU_MAP_DMA) {
        if (request->copy_from_user(request->copy_context, &map,
                request->argument, sizeof(map)) < 0)
            return -EDGE_LINUX_EFAULT;
        return edge_vfio_container_map_dma(&g_objects, handle, &map);
    }
    if (request->command == EDGE_VFIO_IOMMU_UNMAP_DMA) {
        if (!request->copy_to_user || request->copy_from_user(
                request->copy_context, &unmap, request->argument,
                sizeof(unmap)) < 0)
            return -EDGE_LINUX_EFAULT;
        if ((unmap.flags & EDGE_VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP) != 0) {
            edge_vfio_bitmap_t bitmap;
            uint64_t pages;
            uint64_t words;
            if ((unmap.flags & (EDGE_VFIO_DMA_UNMAP_FLAG_ALL |
                                EDGE_VFIO_DMA_UNMAP_FLAG_VADDR)) != 0 ||
                unmap.argsz < sizeof(unmap) + sizeof(bitmap))
                return -EDGE_LINUX_EINVAL;
            if (request->copy_from_user(request->copy_context, &bitmap,
                    request->argument + sizeof(unmap), sizeof(bitmap)) < 0)
                return -EDGE_LINUX_EFAULT;
            if (bitmap.pgsize != EDGE_VFIO_PAGE_SIZE || !bitmap.data ||
                unmap.size == 0 || unmap.size % bitmap.pgsize != 0)
                return -EDGE_LINUX_EINVAL;
            pages = unmap.size / bitmap.pgsize;
            words = (pages + 63u) / 64u;
            if (bitmap.size < words * sizeof(uint64_t))
                return -EDGE_LINUX_ENOSPC;
            for (uint64_t word_index = 0; word_index < words; ++word_index) {
                uint64_t word = 0;
                for (uint32_t bit = 0; bit < 64; ++bit) {
                    uint64_t page = word_index * 64u + bit;
                    int dirty_status;
                    if (page >= pages) break;
                    dirty_status = edge_vfio_container_page_dirty(
                        &g_objects, handle,
                        unmap.iova + page * bitmap.pgsize, bitmap.pgsize);
                    if (dirty_status < 0) return dirty_status;
                    if (dirty_status != 0) word |= UINT64_C(1) << bit;
                }
                if (request->copy_to_user(request->copy_context,
                        bitmap.data + word_index * sizeof(word),
                        &word, sizeof(word)) < 0)
                    return -EDGE_LINUX_EFAULT;
            }
        }
        status = edge_vfio_container_unmap_dma(&g_objects, handle, &unmap);
        if (status == 0 && request->copy_to_user(request->copy_context,
                request->argument, &unmap, sizeof(unmap)) < 0)
            return -EDGE_LINUX_EFAULT;
        return status;
    }
    if (request->command == EDGE_VFIO_IOMMU_DIRTY_PAGES) {
        edge_vfio_iommu_type1_dirty_bitmap_t dirty;
        edge_vfio_iommu_type1_dirty_bitmap_get_t get;
        uint64_t pages;
        uint64_t words;
        if (!request->copy_to_user || request->copy_from_user(
                request->copy_context, &dirty, request->argument,
                sizeof(dirty)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (dirty.argsz < sizeof(dirty) || dirty.flags == 0 ||
            (dirty.flags & (dirty.flags - 1u)) != 0 ||
            (dirty.flags & ~(EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_START |
                             EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP |
                             EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP)) != 0)
            return -EDGE_LINUX_EINVAL;
        if (dirty.flags == EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_START)
            return edge_vfio_container_set_dirty_logging(
                &g_objects, handle, 1);
        if (dirty.flags == EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP)
            return edge_vfio_container_set_dirty_logging(
                &g_objects, handle, 0);
        if (dirty.argsz < sizeof(dirty) + sizeof(get))
            return -EDGE_LINUX_EINVAL;
        if (request->copy_from_user(request->copy_context, &get,
                request->argument + sizeof(dirty), sizeof(get)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (get.bitmap.pgsize != EDGE_VFIO_PAGE_SIZE || get.size == 0 ||
            get.iova % get.bitmap.pgsize != 0 ||
            get.size % get.bitmap.pgsize != 0 || !get.bitmap.data ||
            get.iova > UINT64_MAX - get.size)
            return -EDGE_LINUX_EINVAL;
        pages = get.size / get.bitmap.pgsize;
        words = (pages + 63u) / 64u;
        if (get.bitmap.size < words * sizeof(uint64_t))
            return -EDGE_LINUX_ENOSPC;
        for (uint64_t word_index = 0; word_index < words; ++word_index) {
            uint64_t word = 0;
            for (uint32_t bit = 0; bit < 64; ++bit) {
                uint64_t page = word_index * 64u + bit;
                int dirty_status;
                if (page >= pages) break;
                dirty_status = edge_vfio_container_page_dirty(
                    &g_objects, handle,
                    get.iova + page * get.bitmap.pgsize,
                    get.bitmap.pgsize);
                if (dirty_status < 0) return dirty_status;
                if (dirty_status != 0) word |= UINT64_C(1) << bit;
            }
            if (request->copy_to_user(request->copy_context,
                    get.bitmap.data + word_index * sizeof(word),
                    &word, sizeof(word)) < 0)
                return -EDGE_LINUX_EFAULT;
        }
        return 0;
    }
    return -EDGE_LINUX_ENOTTY;
}

static int copy_device_name(const kernel_ioctl_request_t *request,
                            char name[64]) {
    for (uint32_t index = 0; index < 64u; ++index) {
        if (request->copy_from_user(request->copy_context, &name[index],
                request->argument + index, 1) < 0)
            return -EDGE_LINUX_EFAULT;
        if (name[index] == '\0')
            return index == 0 ? -EDGE_LINUX_EINVAL : 0;
    }
    return -EDGE_LINUX_ENAMETOOLONG;
}

static int group_ioctl(const kernel_ioctl_request_t *request,
                       edge_vfio_handle_t handle) {
    kernel_edge_vfio_file_t container;
    edge_vfio_group_status_t group_status;
    edge_vfio_handle_t device;
    int32_t descriptor;
    char name[64];
    int status;

    if (request->command == EDGE_VFIO_GROUP_GET_STATUS) {
        if (!request->argument || !request->copy_from_user ||
            !request->copy_to_user || request->copy_from_user(
                request->copy_context, &group_status, request->argument,
                sizeof(group_status)) < 0)
            return -EDGE_LINUX_EFAULT;
        status = edge_vfio_group_get_status(&g_objects, handle, &group_status);
        if (status == 0 && request->copy_to_user(request->copy_context,
                request->argument, &group_status,
                sizeof(group_status)) < 0)
            return -EDGE_LINUX_EFAULT;
        return status;
    }
    if (request->command == EDGE_VFIO_GROUP_SET_CONTAINER) {
        if (!request->argument || !request->copy_from_user ||
            request->copy_from_user(request->copy_context, &descriptor,
                request->argument, sizeof(descriptor)) < 0)
            return -EDGE_LINUX_EFAULT;
        status = resolve(descriptor, &container);
        if (status < 0 || container.kind != KERNEL_EDGE_VFIO_FILE_CONTAINER)
            return -EDGE_LINUX_EBADF;
        return edge_vfio_group_set_container(
            &g_objects, handle, container.handle);
    }
    if (request->command == EDGE_VFIO_GROUP_UNSET_CONTAINER)
        return edge_vfio_group_unset_container(&g_objects, handle);
    if (request->command == EDGE_VFIO_GROUP_GET_DEVICE_FD) {
        if (!request->argument || !request->copy_from_user)
            return -EDGE_LINUX_EFAULT;
        status = copy_device_name(request, name);
        if (status < 0) return status;
        status = edge_vfio_group_get_device(&g_objects, handle, name, &device);
        if (status < 0) return status;
        descriptor = install(KERNEL_EDGE_VFIO_FILE_DEVICE, device);
        if (descriptor < 0) {
            (void)edge_vfio_device_release(&g_objects, device);
            return descriptor;
        }
        return descriptor;
    }
    return -EDGE_LINUX_ENOTTY;
}

static int copy_result(const kernel_ioctl_request_t *request,
                       void *value, uint32_t size, int status) {
    if (status == 0 && request->copy_to_user(request->copy_context,
            request->argument, value, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return status;
}

static edge_vfio_iommufd_binding_t *iommufd_binding_find(
        edge_vfio_handle_t device) {
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DEVICES; ++index) {
        edge_vfio_iommufd_binding_t *binding = &g_iommufd_bindings[index];
        if (binding->active && binding->device.slot == device.slot &&
            binding->device.generation == device.generation)
            return binding;
    }
    return 0;
}

static void iommufd_binding_release(edge_vfio_handle_t device) {
    edge_vfio_iommufd_binding_t *binding = iommufd_binding_find(device);
    if (!binding) return;
    if (binding->attached)
        (void)kernel_edge_iommufd_ioas_detach(
            binding->iommufd, binding->attachment_id);
    if (binding->attached)
        (void)kernel_edge_iommufd_pt_release(
            binding->iommufd, binding->pt_id);
    (void)kernel_edge_iommufd_device_unregister(
        binding->iommufd, binding->devid);
    (void)kernel_edge_iommufd_descriptor_release(binding->iommufd);
    binding->active = 0;
}

static int iommufd_device_map(void *context, uint64_t iova,
                              uint64_t user_va, uint64_t length,
                              uint32_t flags) {
    edge_vfio_iommufd_binding_t *binding = context;
    uint32_t dma_flags = 0;

    if (!binding || !binding->active || !binding->attached)
        return -EDGE_LINUX_ENXIO;
    if (flags & EDGE_IOMMU_IOAS_MAP_READABLE)
        dma_flags |= EDGE_VFIO_DMA_MAP_FLAG_READ;
    if (flags & EDGE_IOMMU_IOAS_MAP_WRITEABLE)
        dma_flags |= EDGE_VFIO_DMA_MAP_FLAG_WRITE;
    if (!g_objects.backend.dma_map) return -EDGE_LINUX_EOPNOTSUPP;
    return g_objects.backend.dma_map(g_objects.backend.context, 0,
        binding->vm_cookie, iova, user_va, length, dma_flags);
}

static int iommufd_device_unmap(void *context, uint64_t iova,
                                uint64_t length) {
    edge_vfio_iommufd_binding_t *binding = context;

    if (!binding || !binding->active || !binding->attached)
        return -EDGE_LINUX_ENXIO;
    if (!g_objects.backend.dma_unmap) return -EDGE_LINUX_EOPNOTSUPP;
    return g_objects.backend.dma_unmap(g_objects.backend.context, 0,
        binding->vm_cookie, iova, length);
}

static int device_bind_iommufd(const kernel_ioctl_request_t *request,
                               edge_vfio_handle_t handle) {
    edge_vfio_device_bind_iommufd_t bind;
    edge_vfio_iommufd_binding_t *free_binding = 0;
    edge_iommufd_handle_t iommufd;
    int is_cdev = 0;
    int status;
    if (!request->copy_to_user || request->copy_from_user(
            request->copy_context, &bind, request->argument,
            sizeof(bind)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (bind.argsz < sizeof(bind) || bind.flags != 0 ||
        bind.token_uuid_ptr != 0)
        return -EDGE_LINUX_EINVAL;
    status = edge_vfio_device_query(&g_objects, handle, &is_cdev, 0);
    if (status < 0) return status;
    if (!is_cdev) return -EDGE_LINUX_EINVAL;
    if (iommufd_binding_find(handle)) return -EDGE_LINUX_EBUSY;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DEVICES; ++index) {
        if (!g_iommufd_bindings[index].active) {
            free_binding = &g_iommufd_bindings[index];
            break;
        }
    }
    if (!free_binding) return -EDGE_LINUX_ENOSPC;
    status = kernel_edge_iommufd_descriptor_acquire(bind.iommufd, &iommufd);
    if (status < 0) return status;
    if (g_next_devid == 0) {
        (void)kernel_edge_iommufd_descriptor_release(iommufd);
        return -EDGE_LINUX_EOVERFLOW;
    }
    free_binding->active = 1;
    free_binding->device = handle;
    free_binding->iommufd = iommufd;
    free_binding->devid = g_next_devid++;
    status = kernel_edge_iommufd_device_register(
        iommufd, free_binding->devid);
    if (status < 0) {
        free_binding->active = 0;
        (void)kernel_edge_iommufd_descriptor_release(iommufd);
        return status;
    }
    bind.out_devid = free_binding->devid;
    if (request->copy_to_user(request->copy_context, request->argument,
            &bind, sizeof(bind)) < 0) {
        iommufd_binding_release(handle);
        return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

static int device_attach_iommufd(const kernel_ioctl_request_t *request,
                                 edge_vfio_handle_t handle) {
    edge_vfio_device_attach_iommufd_pt_t attach;
    edge_vfio_iommufd_binding_t *binding = iommufd_binding_find(handle);
    kernel_edge_iommufd_ioas_ops_t ops = {
        .map = iommufd_device_map,
        .unmap = iommufd_device_unmap,
    };
    int status;
    if (request->copy_from_user(request->copy_context, &attach,
            request->argument, sizeof(attach)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (attach.argsz < sizeof(attach) || attach.flags != 0 ||
        attach.pasid != 0)
        return -EDGE_LINUX_EINVAL;
    if (!binding) return -EDGE_LINUX_ENXIO;
    if (binding->attached) return -EDGE_LINUX_EBUSY;
    status = kernel_edge_iommufd_pt_retain(
        binding->iommufd, attach.pt_id, &binding->ioas_id);
    if (status < 0) return status;
    status = edge_vfio_device_context(&g_objects, handle,
        &binding->device_cookie, &binding->vm_cookie);
    if (status < 0) {
        (void)kernel_edge_iommufd_pt_release(
            binding->iommufd, attach.pt_id);
        return status;
    }
    if (binding->vm_cookie == 0) {
        (void)kernel_edge_iommufd_pt_release(
            binding->iommufd, attach.pt_id);
        return -EDGE_LINUX_ENXIO;
    }
    binding->attached = 1;
    binding->pt_id = attach.pt_id;
    status = kernel_edge_iommufd_ioas_attach(binding->iommufd,
        binding->ioas_id, &ops, binding, &binding->attachment_id);
    if (status < 0) {
        (void)kernel_edge_iommufd_pt_release(
            binding->iommufd, attach.pt_id);
        binding->attached = 0;
        binding->ioas_id = 0;
        binding->pt_id = 0;
        binding->vm_cookie = 0;
        binding->device_cookie = 0;
    }
    return status;
}

static int device_detach_iommufd(const kernel_ioctl_request_t *request,
                                 edge_vfio_handle_t handle) {
    edge_vfio_device_detach_iommufd_pt_t detach;
    edge_vfio_iommufd_binding_t *binding = iommufd_binding_find(handle);
    int status;
    if (request->copy_from_user(request->copy_context, &detach,
            request->argument, sizeof(detach)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (detach.argsz < sizeof(detach) || detach.flags != 0 ||
        detach.pasid != 0)
        return -EDGE_LINUX_EINVAL;
    if (!binding) return -EDGE_LINUX_ENXIO;
    if (!binding->attached) return -EDGE_LINUX_ENOENT;
    status = kernel_edge_iommufd_ioas_detach(
        binding->iommufd, binding->attachment_id);
    if (status < 0) return status;
    status = kernel_edge_iommufd_pt_release(
        binding->iommufd, binding->pt_id);
    if (status < 0 && status != -EDGE_LINUX_ENOENT) return status;
    binding->attached = 0;
    binding->ioas_id = 0;
    binding->pt_id = 0;
    binding->attachment_id = 0;
    binding->device_cookie = 0;
    binding->vm_cookie = 0;
    return 0;
}

static int device_ioctl(const kernel_ioctl_request_t *request,
                        edge_vfio_handle_t handle) {
    edge_vfio_device_info_t device_info;
    edge_vfio_region_info_t region_info;
    edge_vfio_irq_info_t irq_info;
    edge_vfio_irq_set_t irq_set;
    uint32_t data_size;

    if (request->command == EDGE_VFIO_DEVICE_RESET)
        return edge_vfio_device_reset(&g_objects, handle);
    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->command == EDGE_VFIO_DEVICE_GET_INFO) {
        if (!request->copy_to_user || request->copy_from_user(
                request->copy_context, &device_info, request->argument,
                sizeof(device_info)) < 0)
            return -EDGE_LINUX_EFAULT;
        return copy_result(request, &device_info, sizeof(device_info),
            edge_vfio_device_get_info(&g_objects, handle, &device_info));
    }
    if (request->command == EDGE_VFIO_DEVICE_GET_REGION_INFO) {
        if (!request->copy_to_user || request->copy_from_user(
                request->copy_context, &region_info, request->argument,
                sizeof(region_info)) < 0)
            return -EDGE_LINUX_EFAULT;
        return copy_result(request, &region_info, sizeof(region_info),
            edge_vfio_device_get_region_info(
                &g_objects, handle, &region_info));
    }
    if (request->command == EDGE_VFIO_DEVICE_GET_IRQ_INFO) {
        if (!request->copy_to_user || request->copy_from_user(
                request->copy_context, &irq_info, request->argument,
                sizeof(irq_info)) < 0)
            return -EDGE_LINUX_EFAULT;
        return copy_result(request, &irq_info, sizeof(irq_info),
            edge_vfio_device_get_irq_info(&g_objects, handle, &irq_info));
    }
    if (request->command == EDGE_VFIO_DEVICE_SET_IRQS) {
        if (request->copy_from_user(request->copy_context, &irq_set,
                request->argument, sizeof(irq_set)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (irq_set.argsz < sizeof(irq_set) ||
            irq_set.argsz - sizeof(irq_set) > EDGE_VFIO_IRQ_DATA_MAX)
            return -EDGE_LINUX_EINVAL;
        data_size = irq_set.argsz - sizeof(irq_set);
        if (data_size != 0 && request->copy_from_user(
                request->copy_context, g_irq_data,
                request->argument + sizeof(irq_set), data_size) < 0)
            return -EDGE_LINUX_EFAULT;
        if ((irq_set.flags & EDGE_VFIO_IRQ_SET_DATA_EVENTFD) != 0) {
            int32_t *eventfds = (int32_t *)(void *)g_irq_data;
            if (data_size != irq_set.count * sizeof(*eventfds))
                return -EDGE_LINUX_EINVAL;
            for (uint32_t index = 0; index < irq_set.count; ++index) {
                int32_t event_id;
                int status;
                if (eventfds[index] < 0)
                    continue;
                status = g_descriptors->resolve_eventfd(
                    g_descriptor_context, eventfds[index], &event_id);
                if (status < 0)
                    return status;
                eventfds[index] = event_id;
            }
        }
        return edge_vfio_device_set_irqs(&g_objects, handle, &irq_set,
            data_size == 0 ? 0 : g_irq_data, data_size);
    }
    if (request->command == EDGE_VFIO_DEVICE_BIND_IOMMUFD)
        return device_bind_iommufd(request, handle);
    if (request->command == EDGE_VFIO_DEVICE_ATTACH_IOMMUFD_PT)
        return device_attach_iommufd(request, handle);
    if (request->command == EDGE_VFIO_DEVICE_DETACH_IOMMUFD_PT)
        return device_detach_iommufd(request, handle);
    if (request->command == EDGE_VFIO_DEVICE_FEATURE ||
        request->command == EDGE_VFIO_MIG_GET_PRECOPY_INFO ||
        request->command == EDGE_VFIO_DEVICE_GET_PCI_HOT_RESET_INFO ||
        request->command == EDGE_VFIO_DEVICE_PCI_HOT_RESET ||
        request->command == EDGE_VFIO_DEVICE_QUERY_GFX_PLANE ||
        request->command == EDGE_VFIO_DEVICE_GET_GFX_DMABUF ||
        request->command == EDGE_VFIO_DEVICE_IOEVENTFD)
        return -EDGE_LINUX_EOPNOTSUPP;
    return -EDGE_LINUX_ENOTTY;
}

int64_t kernel_edge_vfio_ioctl(const kernel_ioctl_request_t *request) {
    kernel_edge_vfio_file_t file;
    int status;
    if (!request || !g_descriptors || resolve(request->descriptor, &file) < 0)
        return -EDGE_LINUX_ENOTTY;
    runtime_lock();
    if (file.kind == KERNEL_EDGE_VFIO_FILE_CONTAINER)
        status = container_ioctl(request, file.handle);
    else if (file.kind == KERNEL_EDGE_VFIO_FILE_GROUP)
        status = group_ioctl(request, file.handle);
    else if (file.kind == KERNEL_EDGE_VFIO_FILE_DEVICE)
        status = device_ioctl(request, file.handle);
    else
        status = -EDGE_LINUX_ENOTTY;
    runtime_unlock();
    return status;
}

int kernel_edge_vfio_descriptor_retain(kernel_edge_vfio_file_kind_t kind,
                                       edge_vfio_handle_t handle) {
    int status;
    runtime_lock();
    if (kind == KERNEL_EDGE_VFIO_FILE_CONTAINER)
        status = edge_vfio_container_retain(&g_objects, handle);
    else if (kind == KERNEL_EDGE_VFIO_FILE_GROUP)
        status = edge_vfio_group_retain(&g_objects, handle);
    else if (kind == KERNEL_EDGE_VFIO_FILE_DEVICE)
        status = edge_vfio_device_retain(&g_objects, handle);
    else
        status = -EDGE_LINUX_EINVAL;
    runtime_unlock();
    return status;
}

int kernel_edge_vfio_descriptor_release(kernel_edge_vfio_file_kind_t kind,
                                        edge_vfio_handle_t handle) {
    int status;
    uint32_t references = 0;
    runtime_lock();
    if (kind == KERNEL_EDGE_VFIO_FILE_CONTAINER)
        status = edge_vfio_container_release(&g_objects, handle);
    else if (kind == KERNEL_EDGE_VFIO_FILE_GROUP)
        status = edge_vfio_group_release(&g_objects, handle);
    else if (kind == KERNEL_EDGE_VFIO_FILE_DEVICE) {
        (void)edge_vfio_device_query(&g_objects, handle, 0, &references);
        status = edge_vfio_device_release(&g_objects, handle);
        if (status == 0 && references == 1u)
            iommufd_binding_release(handle);
    } else
        status = -EDGE_LINUX_EINVAL;
    runtime_unlock();
    return status;
}

static int bind_group(int32_t descriptor, uint64_t vm_cookie, int bind) {
    kernel_edge_vfio_file_t file;
    int status;
    if (resolve(descriptor, &file) < 0 ||
        file.kind != KERNEL_EDGE_VFIO_FILE_GROUP)
        return -EDGE_LINUX_EBADF;
    runtime_lock();
    status = bind ? edge_vfio_group_bind_vm(
        &g_objects, file.handle, vm_cookie) : edge_vfio_group_unbind_vm(
        &g_objects, file.handle, vm_cookie);
    runtime_unlock();
    return status;
}

static int bind_vfio_file(int32_t descriptor, uint64_t vm_cookie, int bind) {
    kernel_edge_vfio_file_t file;
    int status = resolve(descriptor, &file);

    if (status < 0) return -EDGE_LINUX_EBADF;
    runtime_lock();
    if (file.kind == KERNEL_EDGE_VFIO_FILE_GROUP) {
        status = bind ? edge_vfio_group_bind_vm(
            &g_objects, file.handle, vm_cookie) : edge_vfio_group_unbind_vm(
            &g_objects, file.handle, vm_cookie);
    } else if (file.kind == KERNEL_EDGE_VFIO_FILE_DEVICE) {
        status = bind ? edge_vfio_device_bind_vm(
            &g_objects, file.handle, vm_cookie) : edge_vfio_device_unbind_vm(
            &g_objects, file.handle, vm_cookie);
    } else {
        status = -EDGE_LINUX_EBADF;
    }
    runtime_unlock();
    return status;
}

int kernel_edge_vfio_group_bind_descriptor(int32_t descriptor,
                                           uint64_t vm_cookie) {
    return bind_group(descriptor, vm_cookie, 1);
}

int kernel_edge_vfio_group_unbind_descriptor(int32_t descriptor,
                                             uint64_t vm_cookie) {
    return bind_group(descriptor, vm_cookie, 0);
}

int kernel_edge_vfio_bind_descriptor(int32_t descriptor,
                                     uint64_t vm_cookie) {
    return bind_vfio_file(descriptor, vm_cookie, 1);
}

int kernel_edge_vfio_unbind_descriptor(int32_t descriptor,
                                       uint64_t vm_cookie) {
    return bind_vfio_file(descriptor, vm_cookie, 0);
}

int64_t kernel_edge_vfio_device_read(int32_t descriptor, uint64_t offset,
                                     void *buffer, uint32_t size) {
    kernel_edge_vfio_file_t file;
    if (resolve(descriptor, &file) < 0 ||
        file.kind != KERNEL_EDGE_VFIO_FILE_DEVICE)
        return -EDGE_LINUX_EBADF;
    return kernel_edge_vfio_device_read_handle(
        file.handle, offset, buffer, size);
}

int64_t kernel_edge_vfio_device_read_handle(edge_vfio_handle_t handle,
                                            uint64_t offset, void *buffer,
                                            uint32_t size) {
    int64_t status;
    runtime_lock();
    status = edge_vfio_device_read(&g_objects, handle, offset, buffer, size);
    runtime_unlock();
    return status;
}

int64_t kernel_edge_vfio_device_write(int32_t descriptor, uint64_t offset,
                                      const void *buffer, uint32_t size) {
    kernel_edge_vfio_file_t file;
    if (resolve(descriptor, &file) < 0 ||
        file.kind != KERNEL_EDGE_VFIO_FILE_DEVICE)
        return -EDGE_LINUX_EBADF;
    return kernel_edge_vfio_device_write_handle(
        file.handle, offset, buffer, size);
}

int64_t kernel_edge_vfio_device_write_handle(edge_vfio_handle_t handle,
                                             uint64_t offset,
                                             const void *buffer,
                                             uint32_t size) {
    int64_t status;
    runtime_lock();
    status = edge_vfio_device_write(&g_objects, handle, offset, buffer, size);
    runtime_unlock();
    return status;
}

int kernel_edge_vfio_device_mmap(int32_t descriptor, uint64_t offset,
                                 uint64_t size, uint32_t protection,
                                 uint64_t *physical_address) {
    kernel_edge_vfio_file_t file;
    if (resolve(descriptor, &file) < 0 ||
        file.kind != KERNEL_EDGE_VFIO_FILE_DEVICE)
        return -EDGE_LINUX_EBADF;
    return kernel_edge_vfio_device_mmap_handle(
        file.handle, offset, size, protection, physical_address);
}

int kernel_edge_vfio_device_mmap_handle(edge_vfio_handle_t handle,
                                        uint64_t offset, uint64_t size,
                                        uint32_t protection,
                                        uint64_t *physical_address) {
    int status;
    runtime_lock();
    status = edge_vfio_device_mmap(&g_objects, handle, offset,
        size, protection, physical_address);
    runtime_unlock();
    return status;
}
