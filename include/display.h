/* SPDX-License-Identifier: MPL-2.0 */
/* Shared display backend contract for framebuffer and DRM frontends. */

#ifndef EDGEOS_DISPLAY_H
#define EDGEOS_DISPLAY_H

#include <stdint.h>

#define DISPLAY_BACKEND_EXPLICIT_PRESENT (1u << 0)
#define DISPLAY_BACKEND_DYNAMIC_MODE      (1u << 1)

typedef struct display_mode {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_millihz;
    uint32_t flags;
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
int display_backend_set_mode(const display_mode_t *mode);
int display_backend_poll(void);
void display_backend_notify_mode_change(void);
uint64_t display_backend_generation(void);

#endif
