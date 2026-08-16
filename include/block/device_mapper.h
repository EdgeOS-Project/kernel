/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-compatible device-mapper control ABI and shared mapping engine. */

#ifndef EDGEOS_BLOCK_DEVICE_MAPPER_H
#define EDGEOS_BLOCK_DEVICE_MAPPER_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define EDGE_DM_CONTROL_MAJOR 10u
#define EDGE_DM_CONTROL_MINOR 236u
#define EDGE_DM_BLOCK_MAJOR 253u
#define EDGE_DM_MAX_DEVICES 16u
#define EDGE_DM_NAME_LEN 128u
#define EDGE_DM_UUID_LEN 129u

#define EDGE_DM_IOCTL_TYPE 0xfdu

enum edge_dm_command {
    EDGE_DM_VERSION_CMD = 0,
    EDGE_DM_REMOVE_ALL_CMD = 1,
    EDGE_DM_LIST_DEVICES_CMD = 2,
    EDGE_DM_DEV_CREATE_CMD = 3,
    EDGE_DM_DEV_REMOVE_CMD = 4,
    EDGE_DM_DEV_RENAME_CMD = 5,
    EDGE_DM_DEV_SUSPEND_CMD = 6,
    EDGE_DM_DEV_STATUS_CMD = 7,
    EDGE_DM_DEV_WAIT_CMD = 8,
    EDGE_DM_TABLE_LOAD_CMD = 9,
    EDGE_DM_TABLE_CLEAR_CMD = 10,
    EDGE_DM_TABLE_DEPS_CMD = 11,
    EDGE_DM_TABLE_STATUS_CMD = 12,
    EDGE_DM_LIST_VERSIONS_CMD = 13,
    EDGE_DM_TARGET_MSG_CMD = 14,
    EDGE_DM_DEV_SET_GEOMETRY_CMD = 15
};

#define EDGE_DM_READONLY_FLAG             (1u << 0)
#define EDGE_DM_SUSPEND_FLAG              (1u << 1)
#define EDGE_DM_PERSISTENT_DEV_FLAG       (1u << 3)
#define EDGE_DM_STATUS_TABLE_FLAG         (1u << 4)
#define EDGE_DM_ACTIVE_PRESENT_FLAG       (1u << 5)
#define EDGE_DM_INACTIVE_PRESENT_FLAG     (1u << 6)
#define EDGE_DM_BUFFER_FULL_FLAG          (1u << 8)
#define EDGE_DM_QUERY_INACTIVE_TABLE_FLAG (1u << 12)
#define EDGE_DM_UEVENT_GENERATED_FLAG      (1u << 13)
#define EDGE_DM_UUID_FLAG                 (1u << 14)
#define EDGE_DM_SECURE_DATA_FLAG          (1u << 15)
#define EDGE_DM_DATA_OUT_FLAG             (1u << 16)
#define EDGE_DM_DEFERRED_REMOVE_FLAG      (1u << 17)
#define EDGE_DM_INTERNAL_SUSPEND_FLAG     (1u << 18)

typedef struct edge_dm_ioctl {
    uint32_t version[3];
    uint32_t data_size;
    uint32_t data_start;
    uint32_t target_count;
    int32_t open_count;
    uint32_t flags;
    uint32_t event_nr;
    uint32_t padding;
    uint64_t device;
    char name[EDGE_DM_NAME_LEN];
    char uuid[EDGE_DM_UUID_LEN];
    char data[7];
} edge_dm_ioctl_t;

typedef struct edge_dm_target_spec {
    uint64_t sector_start;
    uint64_t length;
    int32_t status;
    uint32_t next;
    char target_type[16];
} edge_dm_target_spec_t;

typedef struct edge_dm_ioctl_request {
    uint64_t device_number;
    uint32_t command;
    uint64_t argument;
    uint8_t privileged;
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
} edge_dm_ioctl_request_t;

_Static_assert(sizeof(edge_dm_ioctl_t) == 312u,
               "Linux device-mapper ioctl ABI size");
_Static_assert(sizeof(edge_dm_target_spec_t) == 40u,
               "Linux device-mapper target ABI size");

void edge_dm_initialize(void);
int edge_dm_is_control_device_number(uint64_t device_number);
int64_t edge_dm_ioctl_execute(const edge_dm_ioctl_request_t *request);
uint32_t edge_dm_device_count(void);
int edge_dm_device_identity_at(uint32_t index, char *name,
                               uint32_t name_capacity,
                               char *node, uint32_t node_capacity,
                               uint32_t *minor);

#endif
