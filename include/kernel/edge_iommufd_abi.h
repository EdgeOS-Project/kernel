/* SPDX-License-Identifier: MPL-2.0 */
/* Linux IOMMUFD userspace ABI values implemented by EdgeOS-owned code. */

#ifndef EDGEOS_KERNEL_EDGE_IOMMUFD_ABI_H
#define EDGEOS_KERNEL_EDGE_IOMMUFD_ABI_H

#include <stdint.h>

#define EDGE_IOMMU_DESTROY          0x00003b80u
#define EDGE_IOMMU_IOAS_ALLOC       0x00003b81u
#define EDGE_IOMMU_IOAS_ALLOW_IOVAS 0x00003b82u
#define EDGE_IOMMU_IOAS_COPY        0x00003b83u
#define EDGE_IOMMU_IOAS_IOVA_RANGES 0x00003b84u
#define EDGE_IOMMU_IOAS_MAP         0x00003b85u
#define EDGE_IOMMU_IOAS_UNMAP       0x00003b86u
#define EDGE_IOMMU_OPTION           0x00003b87u
#define EDGE_IOMMU_VFIO_IOAS        0x00003b88u
#define EDGE_IOMMU_HWPT_ALLOC       0x00003b89u
#define EDGE_IOMMU_GET_HW_INFO      0x00003b8au
#define EDGE_IOMMU_HWPT_SET_DIRTY_TRACKING 0x00003b8bu
#define EDGE_IOMMU_HWPT_GET_DIRTY_BITMAP  0x00003b8cu
#define EDGE_IOMMU_HWPT_INVALIDATE  0x00003b8du
#define EDGE_IOMMU_FAULT_QUEUE_ALLOC 0x00003b8eu
#define EDGE_IOMMU_IOAS_MAP_FILE     0x00003b8fu
#define EDGE_IOMMU_VIOMMU_ALLOC      0x00003b90u
#define EDGE_IOMMU_VDEVICE_ALLOC     0x00003b91u
#define EDGE_IOMMU_IOAS_CHANGE_PROCESS 0x00003b92u
#define EDGE_IOMMU_VEVENTQ_ALLOC     0x00003b93u
#define EDGE_IOMMU_HW_QUEUE_ALLOC    0x00003b94u

#define EDGE_IOMMU_IOAS_MAP_FIXED_IOVA 0x1u
#define EDGE_IOMMU_IOAS_MAP_WRITEABLE  0x2u
#define EDGE_IOMMU_IOAS_MAP_READABLE   0x4u
#define EDGE_IOMMU_IOAS_MAP_VALID_FLAGS 0x7u

#define EDGE_IOMMU_OPTION_RLIMIT_MODE 0u
#define EDGE_IOMMU_OPTION_HUGE_PAGES  1u
#define EDGE_IOMMU_OPTION_OP_SET 0u
#define EDGE_IOMMU_OPTION_OP_GET 1u

#define EDGE_IOMMU_VFIO_IOAS_GET   0u
#define EDGE_IOMMU_VFIO_IOAS_SET   1u
#define EDGE_IOMMU_VFIO_IOAS_CLEAR 2u

#define EDGE_IOMMU_HWPT_ALLOC_NEST_PARENT    0x1u
#define EDGE_IOMMU_HWPT_ALLOC_DIRTY_TRACKING 0x2u
#define EDGE_IOMMU_HWPT_FAULT_ID_VALID       0x4u
#define EDGE_IOMMU_HWPT_ALLOC_PASID          0x8u
#define EDGE_IOMMU_HWPT_DATA_NONE 0u
#define EDGE_IOMMU_HW_CAP_DIRTY_TRACKING 0x1u
#define EDGE_IOMMU_HW_INFO_FLAG_INPUT_TYPE 0x1u
#define EDGE_IOMMU_HWPT_DIRTY_TRACKING_ENABLE 0x1u
#define EDGE_IOMMU_HWPT_GET_DIRTY_BITMAP_NO_CLEAR 0x1u
#define EDGE_IOMMU_HWPT_INVALIDATE_DATA_VTD_S1 0u
#define EDGE_IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3 1u
#define EDGE_IOMMU_VTD_INV_FLAGS_LEAF 0x1u
#define EDGE_IOMMU_VIOMMU_TYPE_DEFAULT 0u
#define EDGE_IOMMU_VIOMMU_TYPE_ARM_SMMUV3 1u
#define EDGE_IOMMU_VIOMMU_TYPE_TEGRA241_CMDQV 2u
#define EDGE_IOMMU_VEVENTQ_TYPE_DEFAULT 0u
#define EDGE_IOMMU_VEVENTQ_TYPE_ARM_SMMUV3 1u
#define EDGE_IOMMU_VEVENTQ_TYPE_TEGRA241_CMDQV 2u
#define EDGE_IOMMU_HW_QUEUE_TYPE_DEFAULT 0u
#define EDGE_IOMMU_HW_QUEUE_TYPE_TEGRA241_CMDQV 1u

typedef struct edge_iommu_destroy {
    uint32_t size;
    uint32_t id;
} edge_iommu_destroy_t;

typedef struct edge_iommu_ioas_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t out_ioas_id;
} edge_iommu_ioas_alloc_t;

typedef struct edge_iommu_iova_range {
    uint64_t start;
    uint64_t last;
} edge_iommu_iova_range_t;

typedef struct edge_iommu_ioas_iova_ranges {
    uint32_t size;
    uint32_t ioas_id;
    uint32_t num_iovas;
    uint32_t reserved;
    uint64_t allowed_iovas;
    uint64_t out_iova_alignment;
} edge_iommu_ioas_iova_ranges_t;

typedef struct edge_iommu_ioas_allow_iovas {
    uint32_t size;
    uint32_t ioas_id;
    uint32_t num_iovas;
    uint32_t reserved;
    uint64_t allowed_iovas;
} edge_iommu_ioas_allow_iovas_t;

typedef struct edge_iommu_ioas_map {
    uint32_t size;
    uint32_t flags;
    uint32_t ioas_id;
    uint32_t reserved;
    uint64_t user_va;
    uint64_t length;
    uint64_t iova;
} edge_iommu_ioas_map_t;

typedef struct edge_iommu_ioas_map_file {
    uint32_t size;
    uint32_t flags;
    uint32_t ioas_id;
    int32_t fd;
    uint64_t start;
    uint64_t length;
    uint64_t iova;
} edge_iommu_ioas_map_file_t;

typedef struct edge_iommu_ioas_copy {
    uint32_t size;
    uint32_t flags;
    uint32_t dst_ioas_id;
    uint32_t src_ioas_id;
    uint64_t length;
    uint64_t dst_iova;
    uint64_t src_iova;
} edge_iommu_ioas_copy_t;

typedef struct edge_iommu_ioas_unmap {
    uint32_t size;
    uint32_t ioas_id;
    uint64_t iova;
    uint64_t length;
} edge_iommu_ioas_unmap_t;

typedef struct edge_iommu_option {
    uint32_t size;
    uint32_t option_id;
    uint16_t op;
    uint16_t reserved;
    uint32_t object_id;
    uint64_t value;
} edge_iommu_option_t;

typedef struct edge_iommu_vfio_ioas {
    uint32_t size;
    uint32_t ioas_id;
    uint16_t op;
    uint16_t reserved;
} edge_iommu_vfio_ioas_t;

typedef struct edge_iommu_hwpt_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t dev_id;
    uint32_t pt_id;
    uint32_t out_hwpt_id;
    uint32_t reserved;
    uint32_t data_type;
    uint32_t data_len;
    uint64_t data_uptr;
    uint32_t fault_id;
    uint32_t reserved2;
} edge_iommu_hwpt_alloc_t;

typedef struct edge_iommu_hw_info {
    uint32_t size;
    uint32_t flags;
    uint32_t dev_id;
    uint32_t data_len;
    uint64_t data_uptr;
    uint32_t data_type;
    uint8_t out_max_pasid_log2;
    uint8_t reserved[3];
    uint64_t out_capabilities;
} edge_iommu_hw_info_t;

typedef struct edge_iommu_hwpt_set_dirty_tracking {
    uint32_t size;
    uint32_t flags;
    uint32_t hwpt_id;
    uint32_t reserved;
} edge_iommu_hwpt_set_dirty_tracking_t;

typedef struct edge_iommu_hwpt_get_dirty_bitmap {
    uint32_t size;
    uint32_t hwpt_id;
    uint32_t flags;
    uint32_t reserved;
    uint64_t iova;
    uint64_t length;
    uint64_t page_size;
    uint64_t data;
} edge_iommu_hwpt_get_dirty_bitmap_t;

typedef struct edge_iommu_hwpt_invalidate {
    uint32_t size;
    uint32_t hwpt_id;
    uint64_t data_uptr;
    uint32_t data_type;
    uint32_t entry_len;
    uint32_t entry_num;
    uint32_t reserved;
} edge_iommu_hwpt_invalidate_t;

typedef struct edge_iommu_hwpt_vtd_s1_invalidate {
    uint64_t addr;
    uint64_t npages;
    uint32_t flags;
    uint32_t reserved;
} edge_iommu_hwpt_vtd_s1_invalidate_t;

typedef struct edge_iommu_fault_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t out_fault_id;
    uint32_t out_fault_fd;
} edge_iommu_fault_alloc_t;

typedef struct edge_iommu_viommu_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t type;
    uint32_t dev_id;
    uint32_t hwpt_id;
    uint32_t out_viommu_id;
    uint32_t data_len;
    uint32_t reserved;
    uint64_t data_uptr;
} edge_iommu_viommu_alloc_t;

typedef struct edge_iommu_vdevice_alloc {
    uint32_t size;
    uint32_t viommu_id;
    uint32_t dev_id;
    uint32_t out_vdevice_id;
    uint64_t virt_id;
} edge_iommu_vdevice_alloc_t;

typedef struct edge_iommu_ioas_change_process {
    uint32_t size;
    uint32_t reserved;
} edge_iommu_ioas_change_process_t;

typedef struct edge_iommu_veventq_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t viommu_id;
    uint32_t type;
    uint32_t veventq_depth;
    uint32_t out_veventq_id;
    uint32_t out_veventq_fd;
    uint32_t reserved;
} edge_iommu_veventq_alloc_t;

typedef struct edge_iommu_hw_queue_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t viommu_id;
    uint32_t type;
    uint32_t index;
    uint32_t out_hw_queue_id;
    uint64_t nesting_parent_iova;
    uint64_t length;
} edge_iommu_hw_queue_alloc_t;

_Static_assert(sizeof(edge_iommu_destroy_t) == 8,
               "IOMMUFD destroy ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_alloc_t) == 12,
               "IOMMUFD IOAS alloc ABI size changed");
_Static_assert(sizeof(edge_iommu_iova_range_t) == 16,
               "IOMMUFD IOVA range ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_iova_ranges_t) == 32,
               "IOMMUFD IOVA ranges ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_allow_iovas_t) == 24,
               "IOMMUFD allow IOVAs ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_map_t) == 40,
               "IOMMUFD IOAS map ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_map_file_t) == 40,
               "IOMMUFD IOAS map file ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_copy_t) == 40,
               "IOMMUFD IOAS copy ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_unmap_t) == 24,
               "IOMMUFD IOAS unmap ABI size changed");
_Static_assert(sizeof(edge_iommu_option_t) == 24,
               "IOMMUFD option ABI size changed");
_Static_assert(sizeof(edge_iommu_vfio_ioas_t) == 12,
               "IOMMUFD VFIO IOAS ABI size changed");
_Static_assert(sizeof(edge_iommu_hwpt_alloc_t) == 48,
               "IOMMUFD HWPT alloc ABI size changed");
_Static_assert(sizeof(edge_iommu_hw_info_t) == 40,
               "IOMMUFD hardware info ABI size changed");
_Static_assert(sizeof(edge_iommu_hwpt_set_dirty_tracking_t) == 16,
               "IOMMUFD dirty tracking ABI size changed");
_Static_assert(sizeof(edge_iommu_hwpt_get_dirty_bitmap_t) == 48,
               "IOMMUFD dirty bitmap ABI size changed");
_Static_assert(sizeof(edge_iommu_hwpt_invalidate_t) == 32,
               "IOMMUFD invalidate ABI size changed");
_Static_assert(sizeof(edge_iommu_hwpt_vtd_s1_invalidate_t) == 24,
               "IOMMUFD VT-d invalidate ABI size changed");
_Static_assert(sizeof(edge_iommu_fault_alloc_t) == 16,
               "IOMMUFD fault allocation ABI size changed");
_Static_assert(sizeof(edge_iommu_viommu_alloc_t) == 40,
               "IOMMUFD vIOMMU allocation ABI size changed");
_Static_assert(sizeof(edge_iommu_vdevice_alloc_t) == 24,
               "IOMMUFD vDevice allocation ABI size changed");
_Static_assert(sizeof(edge_iommu_ioas_change_process_t) == 8,
               "IOMMUFD process transfer ABI size changed");
_Static_assert(sizeof(edge_iommu_veventq_alloc_t) == 32,
               "IOMMUFD vEVENTQ allocation ABI size changed");
_Static_assert(sizeof(edge_iommu_hw_queue_alloc_t) == 40,
               "IOMMUFD hardware queue allocation ABI size changed");

#endif
