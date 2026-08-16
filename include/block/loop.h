/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-compatible file-backed loop block devices. */

#ifndef EDGEOS_BLOCK_LOOP_H
#define EDGEOS_BLOCK_LOOP_H

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "vfs/vfs.h"

#define EDGE_LOOP_DEVICE_COUNT 16u

#define EDGE_LOOP_SET_FD          0x4c00u
#define EDGE_LOOP_CLR_FD          0x4c01u
#define EDGE_LOOP_SET_STATUS64    0x4c04u
#define EDGE_LOOP_GET_STATUS64    0x4c05u
#define EDGE_LOOP_SET_CAPACITY    0x4c07u
#define EDGE_LOOP_SET_DIRECT_IO   0x4c08u
#define EDGE_LOOP_SET_BLOCK_SIZE  0x4c09u
#define EDGE_LOOP_CONFIGURE       0x4c0au
#define EDGE_LOOP_CTL_ADD         0x4c80u
#define EDGE_LOOP_CTL_REMOVE      0x4c81u
#define EDGE_LOOP_CTL_GET_FREE    0x4c82u

#define EDGE_LOOP_FLAG_READ_ONLY  0x00000001u
#define EDGE_LOOP_FLAG_AUTOCLEAR  0x00000004u
#define EDGE_LOOP_FLAG_PARTSCAN   0x00000008u
#define EDGE_LOOP_FLAG_DIRECT_IO  0x00000010u

typedef struct edge_loop_info64 {
    uint64_t device;
    uint64_t inode;
    uint64_t rdevice;
    uint64_t offset;
    uint64_t size_limit;
    uint32_t number;
    uint32_t encryption_type;
    uint32_t encryption_key_size;
    uint32_t flags;
    uint8_t file_name[64];
    uint8_t crypt_name[64];
    uint8_t encryption_key[32];
    uint64_t init[2];
} edge_loop_info64_t;

typedef struct edge_loop_config {
    uint32_t descriptor;
    uint32_t block_size;
    edge_loop_info64_t info;
    uint64_t reserved[8];
} edge_loop_config_t;

_Static_assert(sizeof(edge_loop_info64_t) == 232u,
               "Linux loop_info64 ABI size");
_Static_assert(sizeof(edge_loop_config_t) == 304u,
               "Linux loop_config ABI size");

typedef struct edge_loop_backing_file {
    vfs_superblock_t *superblock;
    vfs_inode_t inode;
    uint64_t device_number;
    uint32_t status_flags;
    char path[64];
} edge_loop_backing_file_t;

typedef int (*edge_loop_resolve_backing_fn)(
    void *context, int32_t descriptor, edge_loop_backing_file_t *backing);

typedef struct edge_loop_ioctl_request {
    uint64_t device_number;
    uint32_t command;
    uint64_t argument;
    uint8_t privileged;
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
    void *resolve_context;
    edge_loop_resolve_backing_fn resolve_backing;
} edge_loop_ioctl_request_t;

void edge_loop_initialize(void);
int edge_loop_is_device_number(uint64_t device_number);
int edge_loop_is_control_device_number(uint64_t device_number);
int64_t edge_loop_ioctl_execute(const edge_loop_ioctl_request_t *request);
int edge_loop_sysfs_path_kind(const char *device_name,
                              const char *relative_path);
int edge_loop_sysfs_read_file(const char *device_name,
                              const char *attribute,
                              char *output, uint32_t capacity);

#endif
