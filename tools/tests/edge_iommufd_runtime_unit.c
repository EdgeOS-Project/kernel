/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/edge_iommufd_runtime.h"
#include "kernel/linux_errno.h"

typedef struct test_state {
    edge_iommufd_handle_t handle;
    int live;
    uint32_t map_calls;
    uint32_t unmap_calls;
    uint32_t fail_map;
    uint32_t file_references;
    uint32_t process_changes;
} test_state_t;

static int install(void *opaque, edge_iommufd_handle_t handle) {
    test_state_t *state = opaque;
    state->handle = handle;
    state->live = 1;
    return 6;
}

static int resolve(void *opaque, int32_t descriptor,
                   edge_iommufd_handle_t *handle) {
    test_state_t *state = opaque;
    if (!state->live || descriptor != 6 || !handle)
        return -EDGE_LINUX_EBADF;
    *handle = state->handle;
    return 0;
}

static int copy_from_user(void *opaque, void *destination,
                          uint64_t source, uint64_t size) {
    (void)opaque;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)size);
    return 0;
}

static int copy_to_user(void *opaque, uint64_t destination,
                        const void *source, uint64_t size) {
    (void)opaque;
    memcpy((void *)(uintptr_t)destination, source, (size_t)size);
    return 0;
}

static int64_t issue(uint32_t command, void *argument) {
    kernel_ioctl_request_t request = {
        .descriptor = 6,
        .command = command,
        .argument = (uint64_t)(uintptr_t)argument,
        .copy_from_user = copy_from_user,
        .copy_to_user = copy_to_user,
        .user_pointer_size = 8,
    };
    return kernel_edge_iommufd_ioctl(&request);
}

static int observe_map(void *opaque, uint64_t iova, uint64_t user_va,
                       uint64_t length, uint32_t flags) {
    test_state_t *state = opaque;
    assert(iova != 0 && user_va != 0 && length != 0 && flags != 0);
    ++state->map_calls;
    if (state->fail_map) {
        state->fail_map = 0;
        return -EDGE_LINUX_EIO;
    }
    return 0;
}

static int observe_unmap(void *opaque, uint64_t iova, uint64_t length) {
    test_state_t *state = opaque;
    assert(iova != 0 && length != 0);
    ++state->unmap_calls;
    return 0;
}

static int file_acquire(void *opaque, int32_t descriptor, uint64_t offset,
                        uint64_t length, uint64_t *user_va,
                        uint64_t *cookie) {
    test_state_t *state = opaque;
    assert(descriptor == 11 && offset == 0x4000 && length == 0x1000);
    *user_va = 0x500000;
    *cookie = 0x55;
    ++state->file_references;
    return 0;
}

static int file_retain(void *opaque, uint64_t cookie) {
    test_state_t *state = opaque;
    assert(cookie == 0x55 && state->file_references != 0);
    ++state->file_references;
    return 0;
}

static void file_release(void *opaque, uint64_t cookie) {
    test_state_t *state = opaque;
    assert(cookie == 0x55 && state->file_references != 0);
    --state->file_references;
}

static int file_change_process(void *opaque, const uint64_t *cookies,
                               uint32_t cookie_count) {
    test_state_t *state = opaque;
    assert(cookie_count == 1 && cookies[0] == 0x55);
    ++state->process_changes;
    return 0;
}

int main(void) {
    test_state_t state = {0};
    kernel_edge_iommufd_descriptor_backend_ops_t descriptors = {
        .install = install,
        .resolve = resolve,
    };
    kernel_edge_iommufd_file_backend_ops_t files = {
        .acquire = file_acquire,
        .retain = file_retain,
        .release = file_release,
        .change_process = file_change_process,
    };
    edge_iommu_ioas_alloc_t first = {.size = sizeof(first)};
    edge_iommu_ioas_alloc_t second = {.size = sizeof(second)};
    edge_iommu_iova_range_t range;
    edge_iommu_ioas_iova_ranges_t ranges = {
        .size = sizeof(ranges),
        .num_iovas = 1,
        .allowed_iovas = (uint64_t)(uintptr_t)&range,
    };
    edge_iommu_ioas_map_t map = {
        .size = sizeof(map),
        .flags = EDGE_IOMMU_IOAS_MAP_FIXED_IOVA |
            EDGE_IOMMU_IOAS_MAP_READABLE | EDGE_IOMMU_IOAS_MAP_WRITEABLE,
        .user_va = 0x200000,
        .length = 0x2000,
        .iova = 0x10000,
    };
    edge_iommu_ioas_map_file_t map_file = {
        .size = sizeof(map_file),
        .flags = EDGE_IOMMU_IOAS_MAP_FIXED_IOVA |
            EDGE_IOMMU_IOAS_MAP_READABLE | EDGE_IOMMU_IOAS_MAP_WRITEABLE,
        .fd = 11,
        .start = 0x4000,
        .length = 0x1000,
        .iova = 0x60000,
    };
    edge_iommu_ioas_change_process_t change_process = {
        .size = sizeof(change_process),
    };
    edge_iommu_ioas_copy_t copy = {
        .size = sizeof(copy),
        .flags = EDGE_IOMMU_IOAS_MAP_FIXED_IOVA |
            EDGE_IOMMU_IOAS_MAP_READABLE,
        .length = 0x2000,
        .dst_iova = 0x30000,
        .src_iova = 0x10000,
    };
    edge_iommu_ioas_unmap_t unmap = {
        .size = sizeof(unmap),
        .iova = 0,
        .length = UINT64_MAX,
    };
    edge_iommu_destroy_t destroy = {.size = sizeof(destroy)};
    edge_iommu_hwpt_alloc_t hwpt = {
        .size = sizeof(hwpt),
        .flags = EDGE_IOMMU_HWPT_ALLOC_DIRTY_TRACKING,
        .dev_id = 17,
    };
    edge_iommu_hw_info_t hw_info = {
        .size = sizeof(hw_info),
        .dev_id = 17,
    };
    uint64_t dirty_bits = 0;
    edge_iommu_hwpt_get_dirty_bitmap_t dirty_bitmap = {
        .size = sizeof(dirty_bitmap),
        .iova = 0x10000,
        .length = 0x4000,
        .page_size = 0x1000,
        .data = (uint64_t)(uintptr_t)&dirty_bits,
    };
    edge_iommu_vfio_ioas_t vfio_ioas = {
        .size = sizeof(vfio_ioas),
        .op = EDGE_IOMMU_VFIO_IOAS_GET,
    };
    kernel_edge_iommufd_ioas_ops_t observer = {
        .map = observe_map,
        .unmap = observe_unmap,
    };
    uint32_t attachment_id = 0;

    assert(kernel_edge_iommufd_descriptor_backend_register(
               &descriptors, &state) == 0);
    assert(kernel_edge_iommufd_file_backend_register(&files, &state) == 0);
    assert(kernel_edge_iommufd_open() == 6);
    assert(issue(EDGE_IOMMU_IOAS_ALLOC, &first) == 0 && first.out_ioas_id != 0);
    assert(issue(EDGE_IOMMU_IOAS_CHANGE_PROCESS, &change_process) == 0 &&
           state.process_changes == 0);
    assert(issue(EDGE_IOMMU_IOAS_ALLOC, &second) == 0 &&
           second.out_ioas_id != first.out_ioas_id);
    assert(kernel_edge_iommufd_device_register(state.handle, 17) == 0);
    assert(issue(EDGE_IOMMU_GET_HW_INFO, &hw_info) == 0 &&
           hw_info.data_len == 0 &&
           (hw_info.out_capabilities &
            EDGE_IOMMU_HW_CAP_DIRTY_TRACKING) != 0);
    assert(issue(EDGE_IOMMU_VFIO_IOAS, &vfio_ioas) ==
           -EDGE_LINUX_ENOENT);
    vfio_ioas.op = EDGE_IOMMU_VFIO_IOAS_SET;
    vfio_ioas.ioas_id = first.out_ioas_id;
    assert(issue(EDGE_IOMMU_VFIO_IOAS, &vfio_ioas) == 0);
    vfio_ioas.op = EDGE_IOMMU_VFIO_IOAS_GET;
    vfio_ioas.ioas_id = 0;
    assert(issue(EDGE_IOMMU_VFIO_IOAS, &vfio_ioas) == 0 &&
           vfio_ioas.ioas_id == first.out_ioas_id);
    ranges.ioas_id = first.out_ioas_id;
    assert(issue(EDGE_IOMMU_IOAS_IOVA_RANGES, &ranges) == 0);
    assert(range.start == 0x1000 && ranges.out_iova_alignment == 0x1000);
    map.ioas_id = first.out_ioas_id;
    assert(issue(EDGE_IOMMU_IOAS_MAP, &map) == 0);
    hwpt.pt_id = first.out_ioas_id;
    assert(issue(EDGE_IOMMU_HWPT_ALLOC, &hwpt) == 0 &&
           hwpt.out_hwpt_id != 0);
    dirty_bitmap.hwpt_id = hwpt.out_hwpt_id;
    assert(issue(EDGE_IOMMU_HWPT_GET_DIRTY_BITMAP, &dirty_bitmap) == 0 &&
           dirty_bits == 0x3);
    {
        uint32_t resolved_ioas = 0;
        assert(kernel_edge_iommufd_pt_retain(
                   state.handle, hwpt.out_hwpt_id, &resolved_ioas) == 0 &&
               resolved_ioas == first.out_ioas_id);
        destroy.id = hwpt.out_hwpt_id;
        assert(issue(EDGE_IOMMU_DESTROY, &destroy) == -EDGE_LINUX_EBUSY);
        assert(kernel_edge_iommufd_pt_release(
                   state.handle, hwpt.out_hwpt_id) == 0);
    }
    assert(kernel_edge_iommufd_ioas_attach(state.handle,
               first.out_ioas_id, &observer, &state,
               &attachment_id) == 0);
    assert(attachment_id != 0 && state.map_calls == 1);
    map.iova = 0x20000;
    map.user_va = 0x220000;
    map.length = 0x1000;
    assert(issue(EDGE_IOMMU_IOAS_MAP, &map) == 0 && state.map_calls == 2);
    state.fail_map = 1;
    map.iova = 0x40000;
    map.user_va = 0x240000;
    assert(issue(EDGE_IOMMU_IOAS_MAP, &map) == -EDGE_LINUX_EIO &&
           state.map_calls == 3);
    unmap.ioas_id = first.out_ioas_id;
    unmap.iova = 0x40000;
    unmap.length = 0x1000;
    assert(issue(EDGE_IOMMU_IOAS_UNMAP, &unmap) == -EDGE_LINUX_ENOENT);
    copy.src_ioas_id = first.out_ioas_id;
    copy.dst_ioas_id = second.out_ioas_id;
    copy.length = 0x2000;
    assert(issue(EDGE_IOMMU_IOAS_COPY, &copy) == 0);
    assert(issue(EDGE_IOMMU_IOAS_CHANGE_PROCESS, &change_process) ==
           -EDGE_LINUX_EINVAL);
    destroy.id = first.out_ioas_id;
    assert(issue(EDGE_IOMMU_DESTROY, &destroy) == -EDGE_LINUX_EBUSY);
    unmap.ioas_id = first.out_ioas_id;
    unmap.iova = 0;
    unmap.length = UINT64_MAX;
    assert(issue(EDGE_IOMMU_IOAS_UNMAP, &unmap) == 0 &&
           unmap.length == 0x3000 && state.unmap_calls == 2);
    destroy.id = first.out_ioas_id;
    assert(issue(EDGE_IOMMU_DESTROY, &destroy) == -EDGE_LINUX_EBUSY);
    assert(kernel_edge_iommufd_ioas_detach(
               state.handle, attachment_id) == 0);
    destroy.id = hwpt.out_hwpt_id;
    assert(issue(EDGE_IOMMU_DESTROY, &destroy) == 0);
    assert(kernel_edge_iommufd_device_unregister(state.handle, 17) == 0);
    destroy.id = first.out_ioas_id;
    assert(issue(EDGE_IOMMU_DESTROY, &destroy) == -EDGE_LINUX_EBUSY);
    vfio_ioas.op = EDGE_IOMMU_VFIO_IOAS_CLEAR;
    vfio_ioas.ioas_id = 0;
    assert(issue(EDGE_IOMMU_VFIO_IOAS, &vfio_ioas) == 0);
    assert(issue(EDGE_IOMMU_DESTROY, &destroy) == 0);
    unmap.ioas_id = second.out_ioas_id;
    unmap.length = UINT64_MAX;
    assert(issue(EDGE_IOMMU_IOAS_UNMAP, &unmap) == 0);
    map_file.ioas_id = second.out_ioas_id;
    assert(issue(EDGE_IOMMU_IOAS_MAP_FILE, &map_file) == 0 &&
           state.file_references == 1);
    assert(issue(EDGE_IOMMU_IOAS_CHANGE_PROCESS, &change_process) == 0 &&
           state.process_changes == 1);
    unmap.ioas_id = second.out_ioas_id;
    unmap.iova = 0;
    unmap.length = UINT64_MAX;
    assert(issue(EDGE_IOMMU_IOAS_UNMAP, &unmap) == 0 &&
           state.file_references == 0);
    destroy.id = second.out_ioas_id;
    assert(issue(EDGE_IOMMU_DESTROY, &destroy) == 0);
    assert(kernel_edge_iommufd_descriptor_retain(state.handle) == 0);
    assert(kernel_edge_iommufd_descriptor_release(state.handle) == 0);
    assert(kernel_edge_iommufd_descriptor_release(state.handle) == 0);

    puts("edge_iommufd_runtime_unit: PASS");
    return 0;
}
