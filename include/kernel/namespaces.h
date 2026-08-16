/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux namespace model.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_NAMESPACES_H
#define EDGEOS_KERNEL_NAMESPACES_H

#include <stdint.h>
#include "kernel/linux_abi.h"

#define EDGE_CLONE_NEWNS      EDGE_LINUX_CLONE_NEWNS
#define EDGE_CLONE_NEWCGROUP  EDGE_LINUX_CLONE_NEWCGROUP
#define EDGE_CLONE_NEWUTS     EDGE_LINUX_CLONE_NEWUTS
#define EDGE_CLONE_NEWIPC     EDGE_LINUX_CLONE_NEWIPC
#define EDGE_CLONE_NEWUSER    EDGE_LINUX_CLONE_NEWUSER
#define EDGE_CLONE_NEWPID     EDGE_LINUX_CLONE_NEWPID
#define EDGE_CLONE_NEWNET     EDGE_LINUX_CLONE_NEWNET
#define EDGE_CLONE_NEWTIME    EDGE_LINUX_CLONE_NEWTIME

#define EDGE_NAMESPACE_CLONE_FLAGS EDGE_LINUX_CLONE_NAMESPACE_FLAGS

typedef enum edge_namespace_kind {
    EDGE_NAMESPACE_CGROUP = 0,
    EDGE_NAMESPACE_IPC,
    EDGE_NAMESPACE_MNT,
    EDGE_NAMESPACE_NET,
    EDGE_NAMESPACE_PID,
    EDGE_NAMESPACE_PID_FOR_CHILDREN,
    EDGE_NAMESPACE_TIME,
    EDGE_NAMESPACE_TIME_FOR_CHILDREN,
    EDGE_NAMESPACE_USER,
    EDGE_NAMESPACE_UTS,
    EDGE_NAMESPACE_KIND_COUNT
} edge_namespace_kind_t;

typedef struct edge_namespace_set {
    uint32_t mount;
    uint32_t cgroup;
    uint32_t ipc;
    uint32_t net;
    uint32_t pid;
    uint32_t pid_children;
    uint32_t time;
    uint32_t time_children;
    uint32_t user;
    uint32_t uts;
    uint8_t owned;
} edge_namespace_set_t;

void edge_namespaces_bootstrap(edge_namespace_set_t *initial,
                               const char *hostname);
int edge_namespaces_inherit(edge_namespace_set_t *child,
                            const edge_namespace_set_t *parent);
int edge_namespaces_clone(edge_namespace_set_t *child,
                          const edge_namespace_set_t *parent,
                          uint64_t clone_flags,
                          uint32_t owner_uid, uint32_t owner_gid);
int edge_namespaces_unshare(edge_namespace_set_t *set, uint64_t flags,
                            uint32_t owner_uid, uint32_t owner_gid);
int edge_namespaces_join(edge_namespace_set_t *set,
                         edge_namespace_kind_t kind, uint32_t id);
void edge_namespaces_release(edge_namespace_set_t *set);

/*
 * Scheduler task identifiers remain global.  These helpers maintain the
 * Linux-visible identifier assigned to a task in each PID namespace where it
 * is visible.  Namespace zero deliberately preserves the global identifier.
 */
int edge_pid_namespace_task_attach(const edge_namespace_set_t *set,
                                   int32_t global_tid);
void edge_pid_namespace_task_detach(int32_t global_tid);
int edge_pid_namespace_global_to_visible(uint32_t namespace_id,
                                         int32_t global_tid,
                                         int32_t *visible_tid_out);
int edge_pid_namespace_visible_to_global(uint32_t namespace_id,
                                         int32_t visible_tid,
                                         int32_t *global_tid_out);

const char *edge_namespace_name(edge_namespace_kind_t kind);
uint64_t edge_namespace_clone_flag(edge_namespace_kind_t kind);
uint32_t edge_namespace_id(const edge_namespace_set_t *set,
                           edge_namespace_kind_t kind);
uint64_t edge_namespace_inode(const edge_namespace_set_t *set,
                              edge_namespace_kind_t kind);
uint64_t edge_namespace_handle_inode(edge_namespace_kind_t kind, uint32_t id);
int edge_namespace_handle_acquire(const edge_namespace_set_t *set,
                                  edge_namespace_kind_t kind,
                                  uint32_t *id_out);
int edge_namespace_handle_retain(edge_namespace_kind_t kind, uint32_t id);
void edge_namespace_handle_release(edge_namespace_kind_t kind, uint32_t id);
int edge_namespace_handle_acquire_inode(edge_namespace_kind_t kind,
                                        uint64_t inode,
                                        uint32_t *id_out);
int edge_namespace_owner_uid(edge_namespace_kind_t kind, uint32_t id,
                             uint32_t *uid_out);

const char *edge_uts_hostname(const edge_namespace_set_t *set);
const char *edge_uts_domainname(const edge_namespace_set_t *set);
int edge_uts_set_hostname(const edge_namespace_set_t *set,
                          const char *name, uint32_t length);
int edge_uts_set_domainname(const edge_namespace_set_t *set,
                            const char *name, uint32_t length);

int edge_userns_read_map(const edge_namespace_set_t *set, int gid_map,
                         char *out, uint32_t max);
int edge_userns_write_map(const edge_namespace_set_t *set, int gid_map,
                          const char *text, uint32_t length,
                          uint32_t writer_uid, uint32_t writer_gid);
int edge_userns_map_from_parent(const edge_namespace_set_t *set, int gid_map,
                                uint32_t outside_id,
                                uint32_t *inside_id_out);
int edge_userns_read_setgroups(const edge_namespace_set_t *set,
                               char *out, uint32_t max);
int edge_userns_write_setgroups(const edge_namespace_set_t *set,
                                const char *text, uint32_t length,
                                uint32_t writer_uid);

#endif
