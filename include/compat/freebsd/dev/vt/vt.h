/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal FreeBSD VT contract for imported framebuffer drivers. */

#ifndef _DEV_VT_VT_H_
#define _DEV_VT_VT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/kernel.h>
#include <sys/terminal.h>

#ifndef _SYS_BUS_H_
#include <edgeos/newbus.h>
#endif

#define CN_DEAD 0
#define CN_INTERNAL 3

#define VT_FB_MAX_WIDTH 4096
#define VT_FB_MAX_HEIGHT 2400
#define PIXEL_WIDTH(width) ((width) / 8)
#define PIXEL_HEIGHT(height) ((height) / 16)

struct thread;
struct vt_device;
struct vt_window;

struct vt_font {
    void *vf_map[4];
    uint8_t *vf_bytes;
    uint32_t vf_height;
    uint32_t vf_width;
    uint32_t vf_map_count[4];
    uint32_t vf_refcount;
};

struct vt_buf {
    unsigned int vb_history_size;
    unsigned int vb_roffset;
    unsigned int vb_curroffset;
    term_char_t **vb_rows;
};

struct vt_window {
    struct vt_buf vw_buf;
    struct vt_font *vw_font;
    term_rect_t vw_draw_area;
};

typedef int vd_probe_t(struct vt_device *device);
typedef int vd_init_t(struct vt_device *device);
typedef void vd_fini_t(struct vt_device *device, void *softc);
typedef void vd_postswitch_t(struct vt_device *device);
typedef void vd_blank_t(struct vt_device *device, term_color_t color);
typedef void vd_bitblt_text_t(struct vt_device *device,
    const struct vt_window *window, const term_rect_t *area);
typedef void vd_invalidate_text_t(struct vt_device *device,
    const term_rect_t *area);
typedef void vd_bitblt_bmp_t(struct vt_device *device,
    const struct vt_window *window, const uint8_t *pattern,
    const uint8_t *mask, unsigned int width, unsigned int height,
    unsigned int x, unsigned int y, term_color_t foreground,
    term_color_t background);
typedef int vd_bitblt_argb_t(struct vt_device *device,
    const struct vt_window *window, const uint8_t *argb,
    unsigned int width, unsigned int height, unsigned int x,
    unsigned int y);
typedef int vd_fb_ioctl_t(struct vt_device *device, unsigned long command,
    char *data, struct thread *thread);
typedef int vd_fb_mmap_t(struct vt_device *device, uint64_t offset,
    uint64_t *physical_address, int protection, char *attribute);
typedef void vd_drawrect_t(struct vt_device *device, int x1, int y1,
    int x2, int y2, int fill, term_color_t color);
typedef void vd_setpixel_t(struct vt_device *device, int x, int y,
    term_color_t color);
typedef void vd_suspend_t(struct vt_device *device);
typedef void vd_resume_t(struct vt_device *device);

struct vt_driver {
    char vd_name[16];
    vd_probe_t *vd_probe;
    vd_init_t *vd_init;
    vd_fini_t *vd_fini;
    vd_blank_t *vd_blank;
    vd_drawrect_t *vd_drawrect;
    vd_setpixel_t *vd_setpixel;
    vd_bitblt_text_t *vd_bitblt_text;
    vd_invalidate_text_t *vd_invalidate_text;
    vd_bitblt_bmp_t *vd_bitblt_bmp;
    vd_bitblt_argb_t *vd_bitblt_argb;
    vd_fb_ioctl_t *vd_fb_ioctl;
    vd_fb_mmap_t *vd_fb_mmap;
    vd_postswitch_t *vd_postswitch;
    vd_suspend_t *vd_suspend;
    vd_resume_t *vd_resume;
    int vd_priority;
    bool vd_bitblt_after_vtbuf_unlock;
};

#define VD_PRIORITY_DUMB 10
#define VD_PRIORITY_GENERIC 100
#define VD_PRIORITY_SPECIFIC 1000

struct vt_device {
    const struct vt_driver *vd_driver;
    void *vd_softc;
    device_t vd_video_dev;
    unsigned int vd_width;
    unsigned int vd_height;
    size_t vd_transpose;
    int vd_flags;
    term_char_t *vd_drawn;
    term_color_t *vd_drawnfg;
    term_color_t *vd_drawnbg;
};

#define VTBUF_GET_FIELD(buffer, row, column) \
    ((buffer)->vb_rows[((buffer)->vb_curroffset + (row)) % \
        (buffer)->vb_history_size][(column)])
#define VTBUF_ISCURSOR(buffer, row, column) \
    vtbuf_iscursor((buffer), (row), (column))

#define VT_DRIVER_DECLARE(name, driver)                                \
    static void name##_edgeos_register(void *argument)                 \
    {                                                                  \
        (void)argument;                                                 \
        vt_driver_register(&(driver));                                  \
    }                                                                  \
    SYSINIT(name##_edgeos_vt_register, SI_SUB_EVENTHANDLER,             \
        SI_ORDER_LAST, name##_edgeos_register, 0)

void vt_driver_register(const struct vt_driver *driver);
int vt_probe_static_drivers(void);
int vt_allocate(const struct vt_driver *driver, void *softc);
int vt_deallocate(const struct vt_driver *driver, void *softc);
void vt_suspend(struct vt_device *device);
void vt_resume(struct vt_device *device);
int vtbuf_iscursor(const struct vt_buf *buffer, int row, int column);
const uint8_t *vtfont_lookup(const struct vt_font *font,
    term_char_t character);
void vt_determine_colors(term_char_t character, int cursor,
    term_color_t *foreground, term_color_t *background);

#endif
