/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD framebuffer contract used by imported display drivers. */

#ifndef _SYS_FBIO_H_
#define _SYS_FBIO_H_

#include <stdint.h>

#include "eventhandler.h"

#ifndef _SYS_BUS_H_
#include "../edgeos/newbus.h"
#endif

struct cdev;

struct fbtype {
    int fb_type;
    int fb_height;
    int fb_width;
    int fb_depth;
    int fb_cmsize;
    int fb_size;
};

struct fb_rgboffs {
    int red;
    int green;
    int blue;
};

typedef int fb_enter_t(void *private_data);
typedef int fb_leave_t(void *private_data);
typedef int fb_setblankmode_t(void *private_data, int mode);

struct fb_info {
    int fb_type;
    int fb_height;
    int fb_width;
    int fb_depth;
    int fb_cmsize;
    int fb_size;
    struct cdev *fb_cdev;
    device_t fb_fbd_dev;
    device_t fb_video_dev;
    fb_enter_t *enter;
    fb_leave_t *leave;
    fb_setblankmode_t *setblankmode;
    uint64_t fb_pbase;
    uintptr_t fb_vbase;
    void *fb_priv;
    const char *fb_name;
    uint32_t fb_flags;
    signed char fb_memattr;
    int fb_stride;
    int fb_bpp;
    uint32_t fb_cmap[16];
    struct fb_rgboffs fb_rgboffs;
};

#define FB_FLAG_NOMMAP 1
#define FB_FLAG_NOWRITE 2
#define FB_FLAG_MEMATTR 4

#define FBTYPE_PCIMISC 13

#define FBTYPE_GET_STRIDE(info) ((info)->fb_size / (info)->fb_height)
#define FBTYPE_GET_BPP(info) ((info)->fb_bpp)
#define FBTYPE_GET_BYTESPP(info) ((info)->fb_bpp / 8)

typedef struct {
    int x;
    int y;
} video_display_start_t;

#define FBIOGTYPE 0x4600UL
#define FBIO_GETWINORG 0x466bUL
#define FBIO_GETDISPSTART 0x466dUL
#define FBIO_GETLINEWIDTH 0x466fUL
#define FBIO_BLANK 0x4673UL
#define FBIO_GETRGBOFFS 0x4674UL

#define V_DISPLAY_ON 0
#define V_DISPLAY_BLANK 1
#define V_DISPLAY_STAND_BY 2
#define V_DISPLAY_SUSPEND 3

static __inline int
register_framebuffer(struct fb_info *info)
{
    EVENTHANDLER_INVOKE(register_framebuffer, info);
    return 0;
}

static __inline int
unregister_framebuffer(struct fb_info *info)
{
    EVENTHANDLER_INVOKE(unregister_framebuffer, info);
    return 0;
}

#endif
