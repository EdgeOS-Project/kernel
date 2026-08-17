/* SPDX-License-Identifier: MPL-2.0 */
/* Shared display backend contract for framebuffer and DRM frontends. */

#ifndef EDGEOS_DISPLAY_H
#define EDGEOS_DISPLAY_H

#include <stdint.h>

#define DISPLAY_BACKEND_EXPLICIT_PRESENT (1u << 0)
#define DISPLAY_BACKEND_DYNAMIC_MODE      (1u << 1)

#define DISPLAY_MODE_PREFERRED     (1u << 0)
#define DISPLAY_MODE_INTERLACE     (1u << 1)
#define DISPLAY_MODE_PHSYNC        (1u << 2)
#define DISPLAY_MODE_NHSYNC        (1u << 3)
#define DISPLAY_MODE_PVSYNC        (1u << 4)
#define DISPLAY_MODE_NVSYNC        (1u << 5)

#define DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ 60000u
#define DISPLAY_MODE_MAX_WIDTH               8192u
#define DISPLAY_MODE_MAX_HEIGHT              8192u
#define DISPLAY_MODE_EDID_MAX_BYTES          1024u
#define DISPLAY_MODE_EDID_MAX_MODES           64u

typedef struct display_mode {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_millihz;
    uint32_t flags;
    uint32_t pixel_clock_khz;
    uint16_t hsync_start;
    uint16_t hsync_end;
    uint16_t htotal;
    uint16_t vsync_start;
    uint16_t vsync_end;
    uint16_t vtotal;
    uint16_t reserved;
} display_mode_t;

typedef struct display_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} display_rect_t;

typedef struct display_backend_ops {
    void (*present_rect)(void *context, uint32_t x, uint32_t y,
                         uint32_t width, uint32_t height);
    void (*present_rects)(void *context, const display_rect_t *rects,
                          uint32_t count);
    int (*get_mode)(void *context, display_mode_t *mode);
    uint32_t (*get_modes)(void *context, display_mode_t *modes,
                          uint32_t capacity);
    uint32_t (*get_edid)(void *context, uint8_t *edid,
                         uint32_t capacity);
    int (*set_mode)(void *context, const display_mode_t *mode);
    int (*poll)(void *context);
} display_backend_ops_t;

typedef struct display_backend {
    const char *name;
    const void *owner;
    void *context;
    uint32_t flags;
    display_backend_ops_t operations;
} display_backend_t;

int display_backend_register(const display_backend_t *backend);
void display_backend_unregister(const void *owner);
void display_backend_reset(void);
int display_backend_snapshot(display_backend_t *backend,
                             uint64_t *generation);
int display_backend_is_owner(const void *owner);
int display_backend_requires_present(void);
void display_backend_present_rect(uint32_t x, uint32_t y,
                                  uint32_t width, uint32_t height);
void display_backend_present_rects(const display_rect_t *rects,
                                   uint32_t count);
int display_backend_get_mode(display_mode_t *mode);
uint32_t display_backend_get_modes(display_mode_t *modes,
                                   uint32_t capacity);
uint32_t display_backend_get_edid(uint8_t *edid, uint32_t capacity);
int display_backend_set_mode(const display_mode_t *mode);
int display_backend_poll(void);
void display_backend_notify_mode_change(void);
uint64_t display_backend_generation(void);

int display_mode_valid(const display_mode_t *mode);
int display_mode_equal(const display_mode_t *left,
                       const display_mode_t *right);
uint64_t display_mode_frame_interval_us(const display_mode_t *mode);
int display_edid_parse(const uint8_t *edid, uint32_t length,
                       display_mode_t *modes, uint32_t capacity,
                       uint32_t *width_mm, uint32_t *height_mm);

#endif
