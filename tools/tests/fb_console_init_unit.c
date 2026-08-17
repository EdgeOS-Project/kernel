/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Host-side regression test for single-pass framebuffer VT initialization.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/*
 * fb_console.c uses interrupt-masking spinlocks in the kernel.  The host test
 * is single-threaded, so provide a lock-compatible shim before including the
 * production implementation.
 */
#define SYS_SPINLOCK_H
typedef struct {
    volatile uint32_t v;
} spinlock_t;

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    assert(lock != 0);
    assert(lock->v == 0);
    lock->v = 1;
    return 0;
}

static inline int spin_trylock_irqsave(spinlock_t *lock, uint64_t *flags_out) {
    assert(lock != 0);
    if (lock->v != 0) return 0;
    lock->v = 1;
    if (flags_out) *flags_out = 0;
    return 1;
}

static inline void spin_unlock_irqrestore(spinlock_t *lock, uint64_t flags) {
    (void)flags;
    assert(lock != 0);
    assert(lock->v == 1);
    lock->v = 0;
}

#include "../../src/fb_console.c"

fb_t fb;
const uint8_t font8x8_basic[128][8];

static int clear_calls;
static int present_calls;
static int present_rect_calls;
static uint32_t last_clear_color;
static uint8_t draw_buffer[800u * 600u * 4u];

void fb_putpixel(int x, int y, uint32_t argb) {
    (void)x;
    (void)y;
    (void)argb;
}

void fb_clear(uint32_t argb) {
    ++clear_calls;
    last_clear_color = argb;
}

bool fb_enable_backbuffer(void) {
    return true;
}

void fb_present(void) {
    ++present_calls;
}

void fb_present_rect(int x, int y, int w, int h) {
    (void)x;
    (void)y;
    (void)w;
    (void)h;
    ++present_rect_calls;
}

uint8_t *fb_get_draw_buffer(void) {
    return draw_buffer;
}

static void seed_stale_vt_state(void) {
    for (int vt = 0; vt < EDGE_FB_VT_COUNT; ++vt) {
        g_vts[vt].cur_col = 7;
        g_vts[vt].cur_row = 5;
        for (int row = 0; row < EDGE_FB_MAX_ROWS; ++row) {
            for (int col = 0; col < EDGE_FB_MAX_COLS; ++col) {
                fb_vt_cell_t *cell =
                    &g_vts[vt].cells[row * EDGE_FB_MAX_COLS + col];
                cell->ch = 'X';
                cell->fg = 1;
                cell->bg = 2;
            }
        }
    }
}

static void assert_all_vts_reset(uint8_t background) {
    for (int vt = 0; vt < EDGE_FB_VT_COUNT; ++vt) {
        assert(g_vts[vt].cur_col == 0);
        assert(g_vts[vt].cur_row == 0);
        for (int row = 0; row < rows; ++row) {
            for (int col = 0; col < cols; ++col) {
                const fb_vt_cell_t *cell =
                    &g_vts[vt].cells[row * EDGE_FB_MAX_COLS + col];
                assert(cell->ch == ' ');
                assert(cell->fg == 15);
                assert(cell->bg == background);
            }
        }
    }
}

int main(void) {
    fb.width = 800;
    fb.height = 600;
    fb.pitch = fb.width * 4u;
    fb.bpp = 32;
    seed_stale_vt_state();

    FB_CONSOLE.init(15, 0);
    assert(clear_calls == 0);
    assert(present_calls == 0);
    assert(present_rect_calls == 0);

    fb_console_reset_all_vts(0);
    assert(clear_calls == 1);
    assert(last_clear_color == 0xFF000000u);
    assert(present_calls == 1);
    assert(present_rect_calls == 0);
    assert_all_vts_reset(0);

    printf("fb_console_init_unit: PASS\n");
    return 0;
}
