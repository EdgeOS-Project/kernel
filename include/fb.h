#ifndef FB_H
#define FB_H

#include <stdint.h>
#include <stdbool.h>

#include "display.h"

typedef struct {
    uint8_t *addr;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t r_mask, g_mask, b_mask;
    uint32_t r_pos, g_pos, b_pos;
} fb_t;

extern fb_t fb;

bool fb_init_from_bootinfo(uint32_t magic, void *mb_info);
bool fb_init_from_multiboot2(void *mb_info);
void fb_install(uint8_t *addr, uint32_t width, uint32_t height, uint32_t pitch,
                uint32_t bpp, uint32_t r_pos, uint32_t g_pos, uint32_t b_pos,
                uint32_t r_mask, uint32_t g_mask, uint32_t b_mask);
void fb_install_physical(uint64_t physical_addr, uint8_t *kernel_addr,
                         uint32_t width, uint32_t height, uint32_t pitch,
                         uint32_t bpp, uint32_t r_pos, uint32_t g_pos,
                         uint32_t b_pos, uint32_t r_mask, uint32_t g_mask,
                         uint32_t b_mask);
void fb_uninstall(uint8_t *expected_kernel_addr);
void fb_debug_dump(void);
void fb_putpixel(int x, int y, uint32_t argb);
void fb_clear(uint32_t argb);
bool fb_enable_backbuffer(void);
void fb_present(void);
void fb_present_rect(int x, int y, int w, int h);
void fb_flush_rect(int x, int y, int w, int h);
void fb_flush_rects(const display_rect_t *rects, uint32_t count);
uint8_t *fb_get_draw_buffer(void);
void fb_note_user_mmap(void);
void fb_release_user_mmap(void);
int fb_user_mmap_active(void);
int fb_user_mmap_write_tracking_required(void);
void fb_note_user_mmap_dirty(uint64_t window_offset, uint64_t len);
void fb_user_mmap_tick(uint32_t ticks);
void fb_user_mmap_request_tick_from_irq(uint32_t ticks);
void fb_user_mmap_pump_deferred(void);
int fb_user_mmap_deferred_due(void);
void fb_fill_rect(int x,int y,int w,int h,uint32_t argb);
void fb_draw_mono_bitmap(int x,int y,int w,int h,const uint8_t*bits,int stride,
                         uint32_t fg,uint32_t bg,bool opaque);
void fb_draw_char(int x,int y,char ch,uint32_t fg,uint32_t bg,bool opaque);
void fb_draw_string(int x,int y,const char* s,uint32_t fg,uint32_t bg,bool opaque);
int fb_get_2m_remap(uint64_t *phys_base, uint32_t *page_count, uint64_t *virt_base);
int fb_get_2m_phys_window(uint64_t *phys_base, uint32_t *page_count, uint64_t *offset_in_first_page);

#endif /* FB_H */
