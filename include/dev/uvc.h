/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux-compatible USB Video Class / V4L2 userspace ABI glue.
 */

#ifndef EDGEOS_DEV_UVC_H
#define EDGEOS_DEV_UVC_H

#include <stdint.h>

#define EDGE_UVC_VIDEO_MAJOR 81u
#define EDGE_UVC_VIDEO_MINOR 0u
#define EDGE_UVC_PATH_VIDEO0 "/dev/video0"

int uvc_available(void);
uint32_t uvc_inode(void);
int uvc_register_from_usb_config(const char *bus, uint8_t slot, uint16_t vendor,
                                 uint16_t product, const uint8_t *cfg,
                                 uint16_t len);
int uvc_path_kind(const char *path);
int uvc_read(const char *path, char *out, uint32_t max);
int uvc_ioctl_kernel(const char *path, uint32_t cmd, void *arg);
uint32_t uvc_ioctl_arg_size(uint32_t cmd);
int uvc_ioctl_type(uint32_t cmd);
int uvc_ioctl_nr(uint32_t cmd);

#endif
