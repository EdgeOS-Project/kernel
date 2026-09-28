/* SPDX-License-Identifier: MPL-2.0 */
/* Shared sysctl ownership helpers for the EdgeOS FreeBSD driver bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYSCTL_H
#define EDGEOS_COMPAT_FREEBSD_SYSCTL_H

struct sysctl_ctx_list;
struct sysctl_oid;

struct sysctl_ctx_list *bsd_sysctl_device_context(void **state,
    const char *name);
struct sysctl_oid *bsd_sysctl_device_tree(void **state, const char *name);
void bsd_sysctl_device_destroy(void **state);

#endif
