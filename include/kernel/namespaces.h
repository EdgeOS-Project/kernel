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
void edge_namespaces_release_runtime(edge_namespace_set_t *set);

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
uint64_t edge_namespace_list_id(edge_namespace_kind_t kind, uint32_t id);
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
int edge_namespace_list_next(const edge_namespace_set_t *current,
                             uint64_t after_list_id,
                             uint64_t owner_user_list_id,
                             uint32_t type_mask,
                             int may_see_all,
                             uint64_t *next_list_id_out,
                             int *any_matching_after_out);

const char *edge_uts_hostname(const edge_namespace_set_t *set);
const char *edge_uts_domainname(const edge_namespace_set_t *set);
int edge_uts_set_hostname(const edge_namespace_set_t *set,
                          const char *name, uint32_t length);
int edge_uts_set_domainname(const edge_namespace_set_t *set,
                            const char *name, uint32_t length);

int edge_userns_read_map(const edge_namespace_set_t *set, int gid_map,
                         char *out, uint32_t max);
int edge_userns_map_opener_allowed(uint32_t namespace_id, int gid_map,
                                   uint32_t opener_uid, int opener_can_setgid);
typedef struct edge_userns_map_diagnostic {
    const char *reason;
    uint32_t namespace_id;
    uint32_t parent_id;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint8_t uid_map_written;
    uint8_t gid_map_written;
    uint8_t setgroups_allowed;
} edge_userns_map_diagnostic_t;

int edge_userns_write_map(const edge_namespace_set_t *set, int gid_map,
                          const char *text, uint32_t length,
                          uint32_t writer_uid, uint32_t writer_gid,
                          int writer_can_setgid,
                          edge_userns_map_diagnostic_t *diagnostic);
int edge_user_namespace_limit_get(uint32_t namespace_id,
                                  uint32_t *limit_out);
int edge_user_namespace_limit_set(uint32_t namespace_id, uint32_t limit);
int edge_userns_map_from_parent(const edge_namespace_set_t *set, int gid_map,
                                uint32_t outside_id,
                                uint32_t *inside_id_out);
int edge_userns_map_to_parent(const edge_namespace_set_t *set, int gid_map,
                              uint32_t inside_id,
                              uint32_t *outside_id_out);
int edge_userns_read_setgroups(const edge_namespace_set_t *set,
                               char *out, uint32_t max);
int edge_userns_write_setgroups(const edge_namespace_set_t *set,
                                const char *text, uint32_t length,
                                uint32_t writer_uid);

#endif
