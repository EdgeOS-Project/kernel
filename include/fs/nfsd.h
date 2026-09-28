/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral NFS server interface. */

#ifndef EDGEOS_FS_NFSD_H
#define EDGEOS_FS_NFSD_H

#include <stdint.h>

#define EDGE_NFSD_EXPORT_READ_ONLY 0x00000001u
#define EDGE_NFSD_EXPORT_ROOT_SQUASH 0x00000002u

int edge_nfsd_initialize(void);
int edge_nfsd_export_add(const char *path, uint32_t flags);
int edge_nfsd_export_remove(const char *path);
uint32_t edge_nfsd_export_count(void);
int edge_nfsd_start(void);
void edge_nfsd_stop(void);
int edge_nfsd_running(void);
int edge_nfsd_boot_start(void);
void edge_nfsd_poll(void);

/* Dispatch one complete ONC RPC message. This is also the test seam. */
int edge_nfsd_rpc_dispatch(const void *request, uint32_t request_bytes,
                           void *response, uint32_t response_capacity,
                           uint32_t *response_bytes);

#endif
