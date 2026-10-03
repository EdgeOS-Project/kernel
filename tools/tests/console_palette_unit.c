/* SPDX-License-Identifier: MPL-2.0 */
/* Host tests for real RGB palette updates and framebuffer VT repainting. */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Use host memory routines while including the freestanding renderer. */
#define STRING_H
#define SYS_SPINLOCK_H
typedef struct { unsigned int held; } spinlock_t;
static uint64_t spin_lock_irqsave(spinlock_t *lock) {
    assert(!lock->held);
    lock->held = 1;
    return 0;
}
static int spin_trylock_irqsave(spinlock_t *lock, uint64_t *flags) {
    if (lock->held) return 0;
    *flags = spin_lock_irqsave(lock);
    return 1;
}
static void spin_unlock_irqrestore(spinlock_t *lock, uint64_t flags) {
    (void)flags;
    assert(lock->held);
    lock->held = 0;
}

#include "../../src/fb_console.c"

#define TEST_WIDTH 144u
#define TEST_HEIGHT 40u
static uint32_t pixels[TEST_WIDTH * TEST_HEIGHT];
static unsigned int pixel_writes, full_presents;
fb_t fb;
const uint8_t font8x8_basic[128][8] = {
    ['X'] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

uint64_t boottime_monotonic_us(void) { return 1000000u; }
int display_backend_requires_present(void) { return 0; }
bool fb_enable_backbuffer(void) { return true; }
uint8_t *fb_get_draw_buffer(void) { return (uint8_t *)pixels; }
void fb_putpixel(int x, int y, uint32_t argb) {
    assert(x >= 0 && y >= 0 && x < (int)TEST_WIDTH && y < (int)TEST_HEIGHT);
    pixels[(unsigned int)y * TEST_WIDTH + (unsigned int)x] = argb;
    ++pixel_writes;
}
void fb_clear(uint32_t argb) {
    for (unsigned int i = 0; i < TEST_WIDTH * TEST_HEIGHT; ++i)
        pixels[i] = argb;
}
void fb_present(void) { ++full_presents; }
void fb_present_rect(int x, int y, int w, int h) {
    (void)x; (void)y; (void)w; (void)h;
}
void fb_flush_rect(int x, int y, int w, int h) {
    (void)x; (void)y; (void)w; (void)h;
}

int main(void) {
    static const uint8_t vga_slot[16] = {
        0, 4, 2, 6, 1, 5, 3, 7, 8, 12, 10, 14, 9, 13, 11, 15
    };
    uint8_t original[EDGE_FB_PALETTE_BYTES];
    uint8_t replacement[EDGE_FB_PALETTE_BYTES];
    uint8_t result[EDGE_FB_PALETTE_BYTES];
    unsigned int before;

    assert(fb_console_get_palette(original) == 0);
    /* ABI slot 1 is red; slot 4 is blue, unlike VGA cell indices. */
    assert(original[3] == 0xaa && original[4] == 0 && original[5] == 0);
    assert(original[12] == 0 && original[13] == 0 && original[14] == 0xaa);
    assert(fb_console_get_palette(0) == -EDGE_LINUX_EFAULT);
    assert(fb_console_set_palette(0) == -EDGE_LINUX_EFAULT);
    for (unsigned int i = 0; i < sizeof(replacement); ++i)
        replacement[i] = (uint8_t)(i * 5u + 7u);

    /* An early set is retained across console initialization. */
    assert(fb_console_set_palette(replacement) == 0);
    assert(pixel_writes == 0 && full_presents == 0);
    fb.width = TEST_WIDTH;
    fb.height = TEST_HEIGHT;
    fb.pitch = TEST_WIDTH * 4u;
    fb.bpp = 32;
    FB_CONSOLE.init(15, 0);
    fb_console_reset_all_vts(0);
    fb_console_set_cursor_enabled(0);
    assert(fb_console_get_palette(result) == 0);
    assert(memcmp(result, replacement, sizeof(result)) == 0);
    assert(fb_console_set_palette(original) == 0);

    /* Populate every foreground/background slot on two different VTs. */
    for (unsigned int i = 0; i < 16u; ++i) {
        fb_console_putchar_vt(1, 'X', vga_slot[i], vga_slot[15u - i]);
        fb_console_putchar_vt(63, 'X', vga_slot[i], vga_slot[15u - i]);
    }
    before = full_presents;
    assert(fb_console_set_palette(replacement) == 0);
    assert(full_presents == before + 1u);
    for (unsigned int i = 0; i < 16u; ++i) {
        unsigned int bg = 15u - i;
        uint32_t fg_color = 0xff000000u | ((uint32_t)replacement[i * 3u] << 16) |
            ((uint32_t)replacement[i * 3u + 1u] << 8) | replacement[i * 3u + 2u];
        uint32_t bg_color = 0xff000000u | ((uint32_t)replacement[bg * 3u] << 16) |
            ((uint32_t)replacement[bg * 3u + 1u] << 8) | replacement[bg * 3u + 2u];
        assert(pixels[i * 9u] == fg_color);
        assert(pixels[i * 9u + 8u] == bg_color);
    }
    before = pixel_writes;
    assert(fb_console_set_palette(replacement) == 0);
    assert(pixel_writes == before);
    fb_console_activate_vt(63);
    assert(pixels[9] == (0xff000000u | ((uint32_t)replacement[3] << 16) |
                        ((uint32_t)replacement[4] << 8) | replacement[5]));

    /* KD_GRAPHICS and framebuffer/DRM ownership defer drawing until release. */
    fb_console_set_present_enabled(0);
    before = pixel_writes;
    assert(fb_console_set_palette(original) == 0);
    assert(pixel_writes == before);
    fb_console_set_present_enabled(1);
    assert(pixels[9] == 0xffaa0000u);
    fb_console_set_fbdev_owned(1);
    before = pixel_writes;
    assert(fb_console_set_palette(replacement) == 0);
    assert(pixel_writes == before);
    fb_console_set_fbdev_owned(0);
    assert(pixel_writes > before);
    fb_console_set_drm_owned(1);
    before = pixel_writes;
    assert(fb_console_set_palette(original) == 0);
    assert(pixel_writes == before);
    fb_console_set_drm_owned(0);
    assert(pixels[9] == 0xffaa0000u);
    assert(fb_console_get_palette(result) == 0);
    assert(memcmp(result, original, sizeof(result)) == 0);
    puts("console_palette_unit: PASS");
    return 0;
}
