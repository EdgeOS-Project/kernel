#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_FBCON_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_FBCON_COMPAT_H

#define nouveau_fb fb
#define pixmap fix
#define buf_align reserved[0]

struct linux_fb_info;
int drm_fb_helper_debug_enter(struct linux_fb_info *info);
int drm_fb_helper_debug_leave(struct linux_fb_info *info);

#endif
