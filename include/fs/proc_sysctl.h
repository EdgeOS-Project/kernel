/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS code. */

#ifndef EDGEOS_FS_PROC_SYSCTL_H
#define EDGEOS_FS_PROC_SYSCTL_H

#include <stdint.h>

typedef enum {
    PROC_SYSCTL_OVERFLOWUID = 0,
    PROC_SYSCTL_OVERFLOWGID = 1,
    PROC_SYSCTL_HOSTNAME = 2,
    PROC_SYSCTL_DOMAINNAME = 3,
    PROC_SYSCTL_BOOT_ID = 4,
    PROC_SYSCTL_FILE_MAX = 5,
    PROC_SYSCTL_NR_OPEN = 6,
    PROC_SYSCTL_INOTIFY_MAX_QUEUED_EVENTS = 7,
    PROC_SYSCTL_INOTIFY_MAX_USER_INSTANCES = 8,
    PROC_SYSCTL_INOTIFY_MAX_USER_WATCHES = 9,
    PROC_SYSCTL_IP_FORWARD = 10,
    PROC_SYSCTL_IP_LOCAL_PORT_RANGE = 11,
    PROC_SYSCTL_THREADS_MAX = 12,
    PROC_SYSCTL_ROOT_MAXKEYS = 13,
    PROC_SYSCTL_OSTYPE = 14,
    PROC_SYSCTL_OSRELEASE = 15,
    PROC_SYSCTL_VERSION = 16,
    PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES = 17,
    PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES = 18,
    PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES = 19
} proc_sysctl_id_t;

uint32_t proc_sysctl_read(proc_sysctl_id_t id);
uint64_t proc_sysctl_nr_open_limit(void);
int proc_sysctl_render(proc_sysctl_id_t id, char *buffer, uint32_t capacity);
int proc_sysctl_write(proc_sysctl_id_t id, const void *buffer, uint32_t length);
int proc_sysctl_render_in_network_namespace(
    proc_sysctl_id_t id, uint32_t network_namespace,
    char *buffer, uint32_t capacity);
int proc_sysctl_write_in_network_namespace(
    proc_sysctl_id_t id, uint32_t network_namespace,
    const void *buffer, uint32_t length);
int proc_parse_s32(const void *buffer, uint32_t length,
                   int32_t minimum, int32_t maximum, int32_t *value_out);

#endif
