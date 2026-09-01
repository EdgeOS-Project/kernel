/* SPDX-License-Identifier: MPL-2.0 */
/* Linux vhost userspace ABI values implemented by EdgeOS-owned code. */

#ifndef EDGEOS_KERNEL_EDGE_VHOST_ABI_H
#define EDGEOS_KERNEL_EDGE_VHOST_ABI_H

#include <stdint.h>

#define EDGE_VHOST_GET_FEATURES         0x8008af00u
#define EDGE_VHOST_SET_FEATURES         0x4008af00u
#define EDGE_VHOST_SET_OWNER            0x0000af01u
#define EDGE_VHOST_RESET_OWNER          0x0000af02u
#define EDGE_VHOST_SET_MEM_TABLE        0x4008af03u
#define EDGE_VHOST_SET_LOG_BASE         0x4008af04u
#define EDGE_VHOST_SET_LOG_FD           0x4004af07u
#define EDGE_VHOST_NEW_WORKER            0x8004af08u
#define EDGE_VHOST_FREE_WORKER           0x4004af09u
#define EDGE_VHOST_SET_VRING_NUM        0x4008af10u
#define EDGE_VHOST_SET_VRING_ADDR       0x4028af11u
#define EDGE_VHOST_SET_VRING_BASE       0x4008af12u
#define EDGE_VHOST_GET_VRING_BASE       0xc008af12u
#define EDGE_VHOST_SET_VRING_ENDIAN     0x4008af13u
#define EDGE_VHOST_GET_VRING_ENDIAN     0x4008af14u
#define EDGE_VHOST_ATTACH_VRING_WORKER  0x4008af15u
#define EDGE_VHOST_GET_VRING_WORKER     0xc008af16u
#define EDGE_VHOST_SET_VRING_KICK       0x4008af20u
#define EDGE_VHOST_SET_VRING_CALL       0x4008af21u
#define EDGE_VHOST_SET_VRING_ERR        0x4008af22u
#define EDGE_VHOST_SET_VRING_BUSYLOOP_TIMEOUT 0x4008af23u
#define EDGE_VHOST_GET_VRING_BUSYLOOP_TIMEOUT 0x4008af24u
#define EDGE_VHOST_SET_BACKEND_FEATURES 0x4008af25u
#define EDGE_VHOST_GET_BACKEND_FEATURES 0x8008af26u
#define EDGE_VHOST_NET_SET_BACKEND      0x4008af30u
#define EDGE_VHOST_SCSI_SET_ENDPOINT    0x40e8af40u
#define EDGE_VHOST_SCSI_CLEAR_ENDPOINT  0x40e8af41u
#define EDGE_VHOST_SCSI_GET_ABI_VERSION 0x4004af42u
#define EDGE_VHOST_SCSI_SET_EVENTS_MISSED 0x4004af43u
#define EDGE_VHOST_SCSI_GET_EVENTS_MISSED 0x4004af44u
#define EDGE_VHOST_VSOCK_SET_GUEST_CID  0x4008af60u
#define EDGE_VHOST_VSOCK_SET_RUNNING    0x4004af61u
#define EDGE_VHOST_VDPA_GET_DEVICE_ID   0x8004af70u
#define EDGE_VHOST_VDPA_GET_STATUS      0x8001af71u
#define EDGE_VHOST_VDPA_SET_STATUS      0x4001af72u
#define EDGE_VHOST_VDPA_GET_CONFIG      0x8008af73u
#define EDGE_VHOST_VDPA_SET_CONFIG      0x4008af74u
#define EDGE_VHOST_VDPA_SET_VRING_ENABLE 0x4008af75u
#define EDGE_VHOST_VDPA_GET_VRING_NUM   0x8002af76u
#define EDGE_VHOST_VDPA_SET_CONFIG_CALL 0x4004af77u
#define EDGE_VHOST_VDPA_GET_IOVA_RANGE  0x8010af78u
#define EDGE_VHOST_VDPA_GET_CONFIG_SIZE 0x8004af79u
#define EDGE_VHOST_VDPA_GET_AS_NUM      0x8004af7au
#define EDGE_VHOST_VDPA_GET_VRING_GROUP 0xc008af7bu
#define EDGE_VHOST_VDPA_SET_GROUP_ASID  0x4008af7cu
#define EDGE_VHOST_VDPA_SUSPEND         0x0000af7du
#define EDGE_VHOST_VDPA_RESUME          0x0000af7eu
#define EDGE_VHOST_VDPA_GET_VRING_DESC_GROUP 0xc008af7fu
#define EDGE_VHOST_VDPA_GET_VQS_COUNT   0x8004af80u
#define EDGE_VHOST_VDPA_GET_GROUP_NUM   0x8004af81u
#define EDGE_VHOST_VDPA_GET_VRING_SIZE  0xc008af82u
#define EDGE_VHOST_GET_FEATURES_ARRAY   0x8008af83u
#define EDGE_VHOST_SET_FEATURES_ARRAY   0x4008af83u
#define EDGE_VHOST_SET_FORK_FROM_OWNER  0x4001af84u
#define EDGE_VHOST_GET_FORK_FROM_OWNER  0x8001af85u

#define EDGE_VHOST_FORK_OWNER_KTHREAD 0u
#define EDGE_VHOST_FORK_OWNER_TASK 1u

#define EDGE_VHOST_ACCESS_RO 0x1u
#define EDGE_VHOST_ACCESS_WO 0x2u
#define EDGE_VHOST_ACCESS_RW 0x3u
#define EDGE_VHOST_IOTLB_MISS 1u
#define EDGE_VHOST_IOTLB_UPDATE 2u
#define EDGE_VHOST_IOTLB_INVALIDATE 3u
#define EDGE_VHOST_IOTLB_ACCESS_FAIL 4u
#define EDGE_VHOST_IOTLB_BATCH_BEGIN 5u
#define EDGE_VHOST_IOTLB_BATCH_END 6u
#define EDGE_VHOST_IOTLB_MSG 0x1u
#define EDGE_VHOST_IOTLB_MSG_V2 0x2u

#define EDGE_VHOST_SCSI_ABI_VERSION 1u

#define EDGE_VHOST_F_LOG_ALL 26u
#define EDGE_VHOST_NET_F_VIRTIO_NET_HDR 27u
#define EDGE_VIRTIO_RING_F_INDIRECT_DESC 28u
#define EDGE_VIRTIO_RING_F_EVENT_IDX 29u
#define EDGE_VIRTIO_F_VERSION_1 32u

#define EDGE_VHOST_VRING_F_LOG 0u
#define EDGE_VHOST_VRING_LITTLE_ENDIAN 0u
#define EDGE_VHOST_VRING_BIG_ENDIAN 1u

typedef struct edge_vhost_vring_state {
    uint32_t index;
    uint32_t num;
} edge_vhost_vring_state_t;

typedef struct edge_vhost_worker_state {
    uint32_t worker_id;
} edge_vhost_worker_state_t;

typedef struct edge_vhost_vring_worker {
    uint32_t index;
    uint32_t worker_id;
} edge_vhost_vring_worker_t;

typedef struct edge_vhost_scsi_target {
    int32_t abi_version;
    char vhost_wwpn[224];
    uint16_t vhost_tpgt;
    uint16_t reserved;
} edge_vhost_scsi_target_t;

typedef struct edge_vhost_vring_file {
    uint32_t index;
    int32_t fd;
} edge_vhost_vring_file_t;

typedef struct edge_vhost_vring_addr {
    uint32_t index;
    uint32_t flags;
    uint64_t desc_user_addr;
    uint64_t used_user_addr;
    uint64_t avail_user_addr;
    uint64_t log_guest_addr;
} edge_vhost_vring_addr_t;

typedef struct edge_vhost_memory_region {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t flags_padding;
} edge_vhost_memory_region_t;

typedef struct edge_vhost_memory {
    uint32_t nregions;
    uint32_t padding;
    edge_vhost_memory_region_t regions[];
} edge_vhost_memory_t;

typedef struct edge_vhost_vdpa_config {
    uint32_t off;
    uint32_t len;
    uint8_t buf[];
} edge_vhost_vdpa_config_t;

typedef struct edge_vhost_vdpa_iova_range {
    uint64_t first;
    uint64_t last;
} edge_vhost_vdpa_iova_range_t;

typedef struct edge_vhost_iotlb_msg {
    uint64_t iova;
    uint64_t size;
    uint64_t uaddr;
    uint8_t perm;
    uint8_t type;
} edge_vhost_iotlb_msg_t;

typedef struct edge_vhost_msg {
    int32_t type;
    union {
        edge_vhost_iotlb_msg_t iotlb;
        uint8_t padding[64];
    } payload;
} edge_vhost_msg_t;

typedef struct edge_vhost_msg_v2 {
    uint32_t type;
    uint32_t asid;
    union {
        edge_vhost_iotlb_msg_t iotlb;
        uint8_t padding[64];
    } payload;
} edge_vhost_msg_v2_t;

typedef struct edge_vhost_features_array {
    uint64_t count;
    uint64_t features[];
} edge_vhost_features_array_t;

_Static_assert(sizeof(edge_vhost_vring_state_t) == 8,
               "vhost vring state ABI size changed");
_Static_assert(sizeof(edge_vhost_vring_file_t) == 8,
               "vhost vring file ABI size changed");
_Static_assert(sizeof(edge_vhost_vring_addr_t) == 40,
               "vhost vring address ABI size changed");
_Static_assert(sizeof(edge_vhost_memory_region_t) == 32,
               "vhost memory region ABI size changed");
_Static_assert(sizeof(edge_vhost_memory_t) == 8,
               "vhost memory header ABI size changed");
_Static_assert(sizeof(edge_vhost_worker_state_t) == 4,
               "vhost worker state ABI size changed");
_Static_assert(sizeof(edge_vhost_vring_worker_t) == 8,
               "vhost vring worker ABI size changed");
_Static_assert(sizeof(edge_vhost_scsi_target_t) == 232,
               "vhost SCSI target ABI size changed");
_Static_assert(sizeof(edge_vhost_vdpa_config_t) == 8,
               "vhost-vDPA config header ABI size changed");
_Static_assert(sizeof(edge_vhost_vdpa_iova_range_t) == 16,
               "vhost-vDPA IOVA range ABI size changed");
_Static_assert(sizeof(edge_vhost_iotlb_msg_t) == 32,
               "vhost IOTLB message ABI size changed");
_Static_assert(sizeof(edge_vhost_msg_t) == 72,
               "vhost message ABI size changed");
_Static_assert(sizeof(edge_vhost_msg_v2_t) == 72,
               "vhost v2 message ABI size changed");
_Static_assert(sizeof(edge_vhost_features_array_t) == 8,
               "vhost feature array header ABI size changed");

#endif
