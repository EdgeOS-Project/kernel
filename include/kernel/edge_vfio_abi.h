/* SPDX-License-Identifier: MPL-2.0 */
/* Linux VFIO userspace ABI values implemented by EdgeOS-owned code. */

#ifndef EDGEOS_KERNEL_EDGE_VFIO_ABI_H
#define EDGEOS_KERNEL_EDGE_VFIO_ABI_H

#include <stdint.h>

#define EDGE_VFIO_API_VERSION 0u

#define EDGE_VFIO_GET_API_VERSION 0x00003b64u
#define EDGE_VFIO_CHECK_EXTENSION  0x00003b65u
#define EDGE_VFIO_SET_IOMMU        0x00003b66u
#define EDGE_VFIO_GROUP_GET_STATUS 0x00003b67u
#define EDGE_VFIO_GROUP_SET_CONTAINER 0x00003b68u
#define EDGE_VFIO_GROUP_UNSET_CONTAINER 0x00003b69u
#define EDGE_VFIO_GROUP_GET_DEVICE_FD 0x00003b6au
#define EDGE_VFIO_DEVICE_GET_INFO  0x00003b6bu
#define EDGE_VFIO_DEVICE_GET_REGION_INFO 0x00003b6cu
#define EDGE_VFIO_DEVICE_GET_IRQ_INFO 0x00003b6du
#define EDGE_VFIO_DEVICE_SET_IRQS  0x00003b6eu
#define EDGE_VFIO_DEVICE_RESET     0x00003b6fu
#define EDGE_VFIO_DEVICE_GET_PCI_HOT_RESET_INFO 0x00003b70u
#define EDGE_VFIO_DEVICE_PCI_HOT_RESET 0x00003b71u
#define EDGE_VFIO_DEVICE_QUERY_GFX_PLANE 0x00003b72u
#define EDGE_VFIO_DEVICE_GET_GFX_DMABUF 0x00003b73u
#define EDGE_VFIO_DEVICE_IOEVENTFD 0x00003b74u
#define EDGE_VFIO_DEVICE_FEATURE 0x00003b75u
#define EDGE_VFIO_DEVICE_BIND_IOMMUFD 0x00003b76u
#define EDGE_VFIO_DEVICE_ATTACH_IOMMUFD_PT 0x00003b77u
#define EDGE_VFIO_DEVICE_DETACH_IOMMUFD_PT 0x00003b78u
#define EDGE_VFIO_MIG_GET_PRECOPY_INFO 0x00003b79u
#define EDGE_VFIO_IOMMU_GET_INFO   0x00003b70u
#define EDGE_VFIO_IOMMU_MAP_DMA    0x00003b71u
#define EDGE_VFIO_IOMMU_UNMAP_DMA  0x00003b72u
#define EDGE_VFIO_IOMMU_ENABLE     0x00003b73u
#define EDGE_VFIO_IOMMU_DISABLE    0x00003b74u
#define EDGE_VFIO_IOMMU_DIRTY_PAGES 0x00003b75u

#define EDGE_VFIO_TYPE1_IOMMU 1u
#define EDGE_VFIO_TYPE1_V2_IOMMU 3u

#define EDGE_VFIO_GROUP_FLAGS_VIABLE 0x1u
#define EDGE_VFIO_GROUP_FLAGS_CONTAINER_SET 0x2u

#define EDGE_VFIO_DMA_MAP_FLAG_READ 0x1u
#define EDGE_VFIO_DMA_MAP_FLAG_WRITE 0x2u
#define EDGE_VFIO_DMA_MAP_VALID_FLAGS \
    (EDGE_VFIO_DMA_MAP_FLAG_READ | EDGE_VFIO_DMA_MAP_FLAG_WRITE)
#define EDGE_VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP 0x1u
#define EDGE_VFIO_DMA_UNMAP_FLAG_ALL 0x2u
#define EDGE_VFIO_DMA_UNMAP_FLAG_VADDR 0x4u
#define EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_START 0x1u
#define EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP 0x2u
#define EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP 0x4u

#define EDGE_VFIO_DEVICE_FLAGS_RESET    0x00000001u
#define EDGE_VFIO_DEVICE_FLAGS_PCI      0x00000002u
#define EDGE_VFIO_DEVICE_FLAGS_PLATFORM 0x00000004u
#define EDGE_VFIO_DEVICE_FLAGS_CAPS     0x00000080u

#define EDGE_VFIO_REGION_INFO_FLAG_READ  0x00000001u
#define EDGE_VFIO_REGION_INFO_FLAG_WRITE 0x00000002u
#define EDGE_VFIO_REGION_INFO_FLAG_MMAP  0x00000004u
#define EDGE_VFIO_REGION_INFO_FLAG_CAPS  0x00000008u

#define EDGE_VFIO_IRQ_INFO_EVENTFD    0x00000001u
#define EDGE_VFIO_IRQ_INFO_MASKABLE   0x00000002u
#define EDGE_VFIO_IRQ_INFO_AUTOMASKED 0x00000004u
#define EDGE_VFIO_IRQ_INFO_NORESIZE   0x00000008u

#define EDGE_VFIO_IRQ_SET_DATA_NONE       0x00000001u
#define EDGE_VFIO_IRQ_SET_DATA_BOOL       0x00000002u
#define EDGE_VFIO_IRQ_SET_DATA_EVENTFD    0x00000004u
#define EDGE_VFIO_IRQ_SET_ACTION_MASK     0x00000008u
#define EDGE_VFIO_IRQ_SET_ACTION_UNMASK   0x00000010u
#define EDGE_VFIO_IRQ_SET_ACTION_TRIGGER  0x00000020u
#define EDGE_VFIO_IRQ_SET_DATA_TYPE_MASK \
    (EDGE_VFIO_IRQ_SET_DATA_NONE | EDGE_VFIO_IRQ_SET_DATA_BOOL | \
     EDGE_VFIO_IRQ_SET_DATA_EVENTFD)
#define EDGE_VFIO_IRQ_SET_ACTION_TYPE_MASK \
    (EDGE_VFIO_IRQ_SET_ACTION_MASK | EDGE_VFIO_IRQ_SET_ACTION_UNMASK | \
     EDGE_VFIO_IRQ_SET_ACTION_TRIGGER)
#define EDGE_VFIO_IRQ_SET_VALID_FLAGS \
    (EDGE_VFIO_IRQ_SET_DATA_TYPE_MASK | EDGE_VFIO_IRQ_SET_ACTION_TYPE_MASK)

#define EDGE_VFIO_PCI_NUM_REGIONS 9u
#define EDGE_VFIO_PCI_NUM_IRQS 5u
#define EDGE_VFIO_PCI_CONFIG_REGION_INDEX 7u
#define EDGE_VFIO_PCI_INTX_IRQ_INDEX 0u
#define EDGE_VFIO_PCI_MSI_IRQ_INDEX 1u
#define EDGE_VFIO_PCI_MSIX_IRQ_INDEX 2u

#define EDGE_VFIO_DEVICE_FEATURE_MASK 0x0000ffffu
#define EDGE_VFIO_DEVICE_FEATURE_GET 0x00010000u
#define EDGE_VFIO_DEVICE_FEATURE_SET 0x00020000u
#define EDGE_VFIO_DEVICE_FEATURE_PROBE 0x00040000u
#define EDGE_VFIO_DEVICE_BIND_FLAG_TOKEN 0x1u
#define EDGE_VFIO_DEVICE_ATTACH_PASID 0x1u
#define EDGE_VFIO_DEVICE_DETACH_PASID 0x1u

typedef struct edge_vfio_group_status {
    uint32_t argsz;
    uint32_t flags;
} edge_vfio_group_status_t;

typedef struct edge_vfio_iommu_type1_info {
    uint32_t argsz;
    uint32_t flags;
    uint64_t iova_pgsizes;
} edge_vfio_iommu_type1_info_t;

typedef struct edge_vfio_iommu_type1_dma_map {
    uint32_t argsz;
    uint32_t flags;
    uint64_t vaddr;
    uint64_t iova;
    uint64_t size;
} edge_vfio_iommu_type1_dma_map_t;

typedef struct edge_vfio_iommu_type1_dma_unmap {
    uint32_t argsz;
    uint32_t flags;
    uint64_t iova;
    uint64_t size;
} edge_vfio_iommu_type1_dma_unmap_t;

typedef struct edge_vfio_bitmap {
    uint64_t pgsize;
    uint64_t size;
    uint64_t data;
} edge_vfio_bitmap_t;

typedef struct edge_vfio_iommu_type1_dirty_bitmap {
    uint32_t argsz;
    uint32_t flags;
} edge_vfio_iommu_type1_dirty_bitmap_t;

typedef struct edge_vfio_iommu_type1_dirty_bitmap_get {
    uint64_t iova;
    uint64_t size;
    edge_vfio_bitmap_t bitmap;
} edge_vfio_iommu_type1_dirty_bitmap_get_t;

typedef struct edge_vfio_precopy_info {
    uint32_t argsz;
    uint32_t flags;
    uint64_t initial_bytes;
    uint64_t dirty_bytes;
} edge_vfio_precopy_info_t;

typedef struct edge_vfio_device_info {
    uint32_t argsz;
    uint32_t flags;
    uint32_t num_regions;
    uint32_t num_irqs;
    uint32_t cap_offset;
    uint32_t padding;
} edge_vfio_device_info_t;

typedef struct edge_vfio_region_info {
    uint32_t argsz;
    uint32_t flags;
    uint32_t index;
    uint32_t cap_offset;
    uint64_t size;
    uint64_t offset;
} edge_vfio_region_info_t;

typedef struct edge_vfio_irq_info {
    uint32_t argsz;
    uint32_t flags;
    uint32_t index;
    uint32_t count;
} edge_vfio_irq_info_t;

typedef struct edge_vfio_irq_set {
    uint32_t argsz;
    uint32_t flags;
    uint32_t index;
    uint32_t start;
    uint32_t count;
} edge_vfio_irq_set_t;

typedef struct edge_vfio_device_feature {
    uint32_t argsz;
    uint32_t flags;
} edge_vfio_device_feature_t;

typedef struct edge_vfio_device_bind_iommufd {
    uint32_t argsz;
    uint32_t flags;
    int32_t iommufd;
    uint32_t out_devid;
    uint64_t token_uuid_ptr;
} edge_vfio_device_bind_iommufd_t;

typedef struct edge_vfio_device_attach_iommufd_pt {
    uint32_t argsz;
    uint32_t flags;
    uint32_t pt_id;
    uint32_t pasid;
} edge_vfio_device_attach_iommufd_pt_t;

typedef struct edge_vfio_device_detach_iommufd_pt {
    uint32_t argsz;
    uint32_t flags;
    uint32_t pasid;
} edge_vfio_device_detach_iommufd_pt_t;

_Static_assert(sizeof(edge_vfio_group_status_t) == 8,
               "VFIO group status ABI size changed");
_Static_assert(sizeof(edge_vfio_iommu_type1_info_t) == 16,
               "VFIO type1 info ABI size changed");
_Static_assert(sizeof(edge_vfio_iommu_type1_dma_map_t) == 32,
               "VFIO DMA map ABI size changed");
_Static_assert(sizeof(edge_vfio_iommu_type1_dma_unmap_t) == 24,
               "VFIO DMA unmap ABI size changed");
_Static_assert(sizeof(edge_vfio_bitmap_t) == 24,
               "VFIO bitmap ABI size changed");
_Static_assert(sizeof(edge_vfio_iommu_type1_dirty_bitmap_t) == 8,
               "VFIO dirty bitmap header ABI size changed");
_Static_assert(sizeof(edge_vfio_iommu_type1_dirty_bitmap_get_t) == 40,
               "VFIO dirty bitmap get ABI size changed");
_Static_assert(sizeof(edge_vfio_precopy_info_t) == 24,
               "VFIO precopy info ABI size changed");
_Static_assert(sizeof(edge_vfio_device_info_t) == 24,
               "VFIO device info ABI size changed");
_Static_assert(sizeof(edge_vfio_region_info_t) == 32,
               "VFIO region info ABI size changed");
_Static_assert(sizeof(edge_vfio_irq_info_t) == 16,
               "VFIO IRQ info ABI size changed");
_Static_assert(sizeof(edge_vfio_irq_set_t) == 20,
               "VFIO IRQ set ABI size changed");
_Static_assert(sizeof(edge_vfio_device_feature_t) == 8,
               "VFIO device feature ABI header size changed");
_Static_assert(sizeof(edge_vfio_device_bind_iommufd_t) == 24,
               "VFIO IOMMUFD bind ABI size changed");
_Static_assert(sizeof(edge_vfio_device_attach_iommufd_pt_t) == 16,
               "VFIO IOMMUFD attach ABI size changed");
_Static_assert(sizeof(edge_vfio_device_detach_iommufd_pt_t) == 12,
               "VFIO IOMMUFD detach ABI size changed");

#endif
