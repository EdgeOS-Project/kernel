#pragma once

#include <stdint.h>
#include "console_backend.h"

/* Linux reserves minor zero for /dev/tty0 and exposes virtual terminals 1-63. */
#define EDGE_FB_VT_COUNT 63

extern const console_backend_t FB_CONSOLE;

void fb_console_present(void);
void fb_console_tick(uint32_t ticks);
void fb_console_request_present(void);
void fb_console_request_tick_from_irq(uint32_t ticks);
void fb_console_pump_deferred(void);
void fb_console_set_cursor_enabled(int enabled);
void fb_console_get_cursor(int *col, int *row);
int fb_console_get_cols(void);
int fb_console_get_rows(void);
void fb_console_set_present_enabled(int enabled);
void fb_console_set_fbdev_owned(int owned);
void fb_console_set_drm_owned(int owned);
void fb_console_activate_vt(int vt);
int fb_console_get_active_vt(void);
void fb_console_reset_all_vts(uint32_t bg);
void fb_console_clear_vt(int vt, uint32_t bg);
void fb_console_putchar_vt(int vt, char ch, uint32_t fg, uint32_t bg);
void fb_console_move_cursor_vt(int vt, int x, int y);
void fb_console_get_cursor_vt(int vt, int *col, int *row);
void fb_console_reverse_index_vt(int vt, uint32_t bg);
void fb_console_erase_in_line_vt(int vt, int mode, uint32_t fg, uint32_t bg);
int fb_console_set_font(const uint8_t *data, uint32_t charcount, uint32_t width,
                        uint32_t height, uint32_t source_pitch);
int fb_console_get_font(uint8_t *data, uint32_t *charcount, uint32_t *width,
                        uint32_t *height, uint32_t dest_pitch);
void fb_console_reset_font(void);
