/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD virtual-terminal color conversion contract. */

#ifndef EDGEOS_COMPAT_FREEBSD_VT_TERMCOLORS_H
#define EDGEOS_COMPAT_FREEBSD_VT_TERMCOLORS_H

#include <stdint.h>

struct fb_info;

enum vt_color_format {
    COLOR_FORMAT_BW = 0,
    COLOR_FORMAT_GRAY,
    COLOR_FORMAT_VGA,
    COLOR_FORMAT_RGB,
    COLOR_FORMAT_ARGB,
};

#define NCOLORS 16

int vt_config_cons_colors(struct fb_info *info, int format,
    uint32_t red_max, int red_offset, uint32_t green_max,
    int green_offset, uint32_t blue_max, int blue_offset);

#endif
