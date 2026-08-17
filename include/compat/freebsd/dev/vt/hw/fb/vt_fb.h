/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD generic framebuffer entry points used by VirtIO GPU. */

#ifndef _DEV_VT_HW_FB_VT_FB_H_
#define _DEV_VT_HW_FB_VT_FB_H_

#include <sys/fbio.h>
#include <dev/vt/vt.h>

int vt_fb_attach(struct fb_info *info);
int vt_fb_detach(struct fb_info *info);
void vt_fb_resume(struct vt_device *device);
void vt_fb_suspend(struct vt_device *device);

vd_init_t vt_fb_init;
vd_fini_t vt_fb_fini;
vd_blank_t vt_fb_blank;
vd_bitblt_text_t vt_fb_bitblt_text;
vd_invalidate_text_t vt_fb_invalidate_text;
vd_bitblt_bmp_t vt_fb_bitblt_bitmap;
vd_bitblt_argb_t vt_fb_bitblt_argb;
vd_drawrect_t vt_fb_drawrect;
vd_setpixel_t vt_fb_setpixel;
vd_postswitch_t vt_fb_postswitch;
vd_fb_ioctl_t vt_fb_ioctl;
vd_fb_mmap_t vt_fb_mmap;

#endif
