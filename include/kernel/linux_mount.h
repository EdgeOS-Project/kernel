/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux mount ABI policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_MOUNT_H
#define EDGEOS_KERNEL_LINUX_MOUNT_H

#include <stdint.h>

#include "kernel/namespaces.h"

#define EDGE_LINUX_MS_RDONLY      0x00000001ULL
#define EDGE_LINUX_MS_NOSUID      0x00000002ULL
#define EDGE_LINUX_MS_NODEV       0x00000004ULL
#define EDGE_LINUX_MS_NOEXEC      0x00000008ULL
#define EDGE_LINUX_MS_SYNCHRONOUS 0x00000010ULL
#define EDGE_LINUX_MS_REMOUNT     0x00000020ULL
#define EDGE_LINUX_MS_MANDLOCK    0x00000040ULL
#define EDGE_LINUX_MS_DIRSYNC     0x00000080ULL
#define EDGE_LINUX_MS_NOSYMFOLLOW 0x00000100ULL
#define EDGE_LINUX_MS_NOATIME     0x00000400ULL
#define EDGE_LINUX_MS_NODIRATIME  0x00000800ULL
#define EDGE_LINUX_MS_BIND        0x00001000ULL
#define EDGE_LINUX_MS_MOVE        0x00002000ULL
#define EDGE_LINUX_MS_REC         0x00004000ULL
#define EDGE_LINUX_MS_SILENT      0x00008000ULL
#define EDGE_LINUX_MS_POSIXACL    0x00010000ULL
#define EDGE_LINUX_MS_UNBINDABLE  0x00020000ULL
#define EDGE_LINUX_MS_PRIVATE     0x00040000ULL
#define EDGE_LINUX_MS_SLAVE       0x00080000ULL
#define EDGE_LINUX_MS_SHARED      0x00100000ULL
#define EDGE_LINUX_MS_RELATIME    0x00200000ULL
#define EDGE_LINUX_MS_I_VERSION   0x00800000ULL
#define EDGE_LINUX_MS_STRICTATIME 0x01000000ULL
#define EDGE_LINUX_MS_LAZYTIME    0x02000000ULL
#define EDGE_LINUX_MS_MGC_VAL     0xc0ed0000ULL
#define EDGE_LINUX_MS_MGC_MSK     0xffff0000ULL

#define EDGE_LINUX_MNT_FORCE       0x1u
#define EDGE_LINUX_MNT_DETACH      0x2u
#define EDGE_LINUX_MNT_EXPIRE      0x4u
#define EDGE_LINUX_UMOUNT_NOFOLLOW 0x8u

#define EDGE_LINUX_MOUNT_ATTR_RDONLY      0x00000001ULL
#define EDGE_LINUX_MOUNT_ATTR_NOSUID      0x00000002ULL
#define EDGE_LINUX_MOUNT_ATTR_NODEV       0x00000004ULL
#define EDGE_LINUX_MOUNT_ATTR_NOEXEC      0x00000008ULL
#define EDGE_LINUX_MOUNT_ATTR_NOATIME     0x00000010ULL
#define EDGE_LINUX_MOUNT_ATTR_STRICTATIME 0x00000020ULL
#define EDGE_LINUX_MOUNT_ATTR_ATIME       0x00000070ULL
#define EDGE_LINUX_MOUNT_ATTR_NODIRATIME  0x00000080ULL
#define EDGE_LINUX_MOUNT_ATTR_IDMAP       0x00100000ULL
#define EDGE_LINUX_MOUNT_ATTR_NOSYMFOLLOW 0x00200000ULL

int64_t kernel_linux_mount(char *source, char *target,
                           const char *filesystem, uint64_t flags,
                           const char *data, char *workspace,
                           uint32_t workspace_capacity);
int64_t kernel_linux_mount_setattr(const char *target, uint64_t attr_set,
                                   uint64_t attr_clear,
                                   uint64_t propagation, int recursive);
int64_t kernel_linux_umount(char *target, uint64_t flags, char *workspace,
                            uint32_t workspace_capacity);
int kernel_linux_mount_monitor_target(const char *path, int32_t current_pid,
                                      int32_t *target_pid);
/* The caller owns one namespace-handle reference after a successful call. */
int kernel_linux_namespace_mount_acquire(const char *path,
                                         edge_namespace_kind_t *kind_out,
                                         uint32_t *id_out);
int kernel_linux_namespace_path_parse(
    const char *path, int32_t self_tgid, int32_t self_tid,
    int32_t *owner_tgid_out, int32_t *target_tid_out,
    edge_namespace_kind_t *kind_out);
int64_t kernel_linux_pivot_root(char *new_root, char *put_old,
                                char *workspace,
                                uint32_t workspace_capacity);

#endif
