/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_DEV_DEVTMPFS_H
#define EDGEOS_DEV_DEVTMPFS_H

int devtmpfs_mount(const char *device, const char *target);
int devtmpfs_populate_standard_nodes(const char *mountpoint);
int devtmpfs_refresh_block_nodes(void);
int devtmpfs_refresh_input_nodes(void);
int devtmpfs_refresh_audio_nodes(void);
int devtmpfs_refresh_bsd_bridge_nodes(void);

#endif
