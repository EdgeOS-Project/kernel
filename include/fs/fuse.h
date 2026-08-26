/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-compatible FUSE transport and VFS integration shared by all architectures. */

#ifndef EDGEOS_FS_FUSE_H
#define EDGEOS_FS_FUSE_H

#include <stdint.h>

#define EDGE_FUSE_DEVICE_MAJOR 10u
#define EDGE_FUSE_DEVICE_MINOR 229u
#define EDGE_FUSE_DEVICE_RDEV \
    (((uint64_t)EDGE_FUSE_DEVICE_MAJOR << 8) | EDGE_FUSE_DEVICE_MINOR)
#define EDGE_FUSE_DEVICE_PATH "/dev/fuse"

/* Return value used by the character-device multiplexer for unrelated nodes. */
#define EDGE_FUSE_NOT_HANDLED (-4096)

#define EDGE_FUSE_IO_URING_CMD_REGISTER 1u
#define EDGE_FUSE_IO_URING_CMD_COMMIT_AND_FETCH 2u
#define EDGE_FUSE_DEV_IOC_SYNC_INIT 0x0000e503u

typedef struct edge_fuse_uring_command {
    int32_t ring_id;
    int32_t descriptor;
    uint64_t user_data;
    uint64_t address_space;
    uint64_t headers_address;
    uint64_t payload_address;
    uint64_t commit_id;
    uint32_t headers_length;
    uint32_t payload_length;
    uint16_t qid;
    uint8_t operation;
    uint8_t reserved;
} edge_fuse_uring_command_t;

int edge_fuse_mount(uint64_t description_identity, const char *target,
                    const char *filesystem, const char *options);
int edge_fuse_device_read(uint64_t description_identity, void *buffer,
                          uint32_t length);
int edge_fuse_device_write(uint64_t description_identity, const void *buffer,
                           uint32_t length);
int edge_fuse_device_poll(uint64_t description_identity, uint32_t events);
int edge_fuse_device_ioctl(uint64_t description_identity, uint32_t command);
int edge_fuse_device_uring_cmd(
    uint64_t description_identity,
    const edge_fuse_uring_command_t *command);
void edge_fuse_device_close(uint64_t description_identity);
int edge_fuse_is_device(uint64_t linux_rdev);

/*
 * ARM64 replays a system call when a FUSE reply requires another userspace
 * task to run.  These hooks keep completed protocol steps available across
 * that replay while the architecture-neutral FUSE core remains shared.
 */
void edge_fuse_syscall_replay_begin(uintptr_t context_token);
void edge_fuse_syscall_replay_complete(uintptr_t context_token);

#endif
