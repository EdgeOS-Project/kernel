// console.c — backend-agnostic console that forwards to the selected console backend
#include "console.h"
#include "console_backend.h"
#include "fb.h"
#include "fb_console.h"
#include "keyboard.h"
#include "kernel/tty_session.h"
#include "serial_console.h"
#include "string.h"
#include "sys/bootlog.h"
#include "sys/spinlock.h"
#include <stdint.h>
#include <stdarg.h>

typedef struct {
    uint32_t fg;
    uint32_t bg;
    uint32_t default_fg;
    uint32_t default_bg;
    int esc_state;
    int esc_qmark;
    int esc_bang;
    int esc_params[8];
    int esc_param_count;
    int esc_cur;
    int saved_col;
    int saved_row;
    uint32_t utf8_code;
    int utf8_remaining;
} console_state_t;

static const console_backend_t* g_be = 0;
static console_state_t g_console_state[EDGE_FB_VT_COUNT + 1];
static int g_kernel_log_timestamps;
static int g_kernel_log_at_line_start = 1;
static char g_kernel_log_line[512];
static uint32_t g_kernel_log_line_len;
static spinlock_t g_printf_lock;
static volatile int g_kernel_console_loglevel = 7;
static volatile int g_kernel_saved_console_loglevel = -1;
static volatile unsigned int g_console_output_batch_depth;

#define EDGE_KERNEL_DEFAULT_MESSAGE_LOGLEVEL 4
#define EDGE_KERNEL_MINIMUM_CONSOLE_LOGLEVEL 1

static int console_is_fb_backend(void) {
    return g_be == &FB_CONSOLE;
}

static int console_clamp_vt(int vt) {
    if (vt < 1 || vt > EDGE_FB_VT_COUNT) return 1;
    return vt;
}

static int console_current_vt(void) {
    if (console_is_fb_backend()) return console_clamp_vt(fb_console_get_active_vt());
    return 1;
}

static console_state_t *console_state_for_vt(int vt) {
    return &g_console_state[console_clamp_vt(vt)];
}

static int console_cols(void) {
    if (g_be && g_be->get_cols) {
        int c = g_be->get_cols();
        if (c > 0) return c;
    }
    return 80;
}

static int console_rows(void) {
    if (g_be && g_be->get_rows) {
        int r = g_be->get_rows();
        if (r > 0) return r;
    }
    return 25;
}

static void console_get_cursor_vt(int vt, int *x, int *y) {
    int cx = 0, cy = 0;
    if (console_is_fb_backend()) {
        fb_console_get_cursor_vt(vt, &cx, &cy);
    } else if (g_be && g_be->get_cursor) {
        g_be->get_cursor(&cx, &cy);
    }
    if (x) *x = cx;
    if (y) *y = cy;
}

static void console_move_cursor_vt(int vt, uint16_t x, uint16_t y) {
    if (console_is_fb_backend()) {
        fb_console_move_cursor_vt(vt, (int)x, (int)y);
    } else if (g_be && g_be->move_cursor) {
        g_be->move_cursor((int)x, (int)y);
    }
}

static void console_emit_raw_vt(int vt, char ch, uint32_t fg, uint32_t bg) {
    if (console_is_fb_backend()) {
        fb_console_putchar_vt(vt, ch, fg, bg);
    } else if (g_be && g_be->putchar) {
        g_be->putchar(ch);
    }
}

static void console_erase_in_line_vt(int vt, int mode, uint32_t fg, uint32_t bg) {
    if (console_is_fb_backend()) {
        fb_console_erase_in_line_vt(vt, mode, fg, bg);
    } else if (g_be && g_be->erase_in_line) {
        g_be->erase_in_line(mode);
    }
}

static void console_reverse_index_vt(int vt, uint32_t bg) {
    int x;
    int y;
    console_get_cursor_vt(vt, &x, &y);
    if (y > 0) {
        console_move_cursor_vt(vt, (uint16_t)x, (uint16_t)(y - 1));
    } else if (console_is_fb_backend()) {
        fb_console_reverse_index_vt(vt, bg);
    }
}

static void console_reset_vt_state(int vt, uint32_t fore_color,
                                   uint32_t back_color) {
    console_state_t *st = console_state_for_vt(vt);
    st->fg = fore_color;
    st->bg = back_color;
    st->default_fg = fore_color;
    st->default_bg = back_color;
    st->esc_state = 0;
    st->esc_qmark = 0;
    st->esc_bang = 0;
    st->esc_param_count = 0;
    st->esc_cur = -1;
    st->saved_col = 0;
    st->saved_row = 0;
    st->utf8_code = 0;
    st->utf8_remaining = 0;
}

static void console_clear_vt_internal(int vt, uint32_t fore_color,
                                      uint32_t back_color) {
    console_reset_vt_state(vt, fore_color, back_color);
    if (console_is_fb_backend()) {
        fb_console_clear_vt(vt, back_color);
    } else {
        if (g_be && g_be->set_color) g_be->set_color(fore_color, back_color);
        if (g_be && g_be->clear) g_be->clear();
    }
}

static uint32_t ansi_to_vga_idx(int idx) {
    static const uint8_t lut[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
    return (uint32_t)lut[idx & 7];
}

static void console_erase_chars_at_cursor_vt(int vt, console_state_t *st, int n) {
    int x, y;
    int cols = console_cols();
    if (!st || n <= 0) return;
    console_get_cursor_vt(vt, &x, &y);
    if (x < 0 || x >= cols) return;
    if (n > cols - x) n = cols - x;
    for (int i = 0; i < n; ++i) {
        console_move_cursor_vt(vt, (uint16_t)(x + i), (uint16_t)y);
        console_emit_raw_vt(vt, ' ', st->fg, st->bg);
    }
    console_move_cursor_vt(vt, (uint16_t)x, (uint16_t)y);
}

static void console_erase_in_display_vt(int vt, console_state_t *st, int mode) {
    int x, y;
    int rows = console_rows();
    if (!st || rows <= 0) return;
    console_get_cursor_vt(vt, &x, &y);
    if (y < 0) y = 0;
    if (y >= rows) y = rows - 1;

    if (mode == 2 || mode == 3) {
        console_clear_vt_internal(vt, st->default_fg, st->default_bg);
        return;
    }

    if (mode == 0) {
        console_erase_in_line_vt(vt, 0, st->fg, st->bg);
        for (int r = y + 1; r < rows; ++r) {
            console_move_cursor_vt(vt, 0, (uint16_t)r);
            console_erase_in_line_vt(vt, 2, st->fg, st->bg);
        }
    } else if (mode == 1) {
        for (int r = 0; r < y; ++r) {
            console_move_cursor_vt(vt, 0, (uint16_t)r);
            console_erase_in_line_vt(vt, 2, st->fg, st->bg);
        }
        console_move_cursor_vt(vt, 0, (uint16_t)y);
        console_erase_in_line_vt(vt, 1, st->fg, st->bg);
    }
    console_move_cursor_vt(vt, (uint16_t)x, (uint16_t)y);
}

static void console_apply_sgr(console_state_t *st) {
    int n = st->esc_param_count;
    if (st->esc_cur >= 0 && n < (int)(sizeof(st->esc_params) / sizeof(st->esc_params[0]))) {
        st->esc_params[n++] = st->esc_cur;
    }
    if (n == 0) {
        st->fg = st->default_fg;
        st->bg = st->default_bg;
        return;
    }
    for (int i = 0; i < n; ++i) {
        int p = st->esc_params[i];
        if (p == 0) {
            st->fg = st->default_fg;
            st->bg = st->default_bg;
        } else if (p == 39) {
            st->fg = st->default_fg;
        } else if (p == 49) {
            st->bg = st->default_bg;
        } else if (p >= 30 && p <= 37) {
            st->fg = ansi_to_vga_idx(p - 30);
        } else if (p >= 40 && p <= 47) {
            st->bg = ansi_to_vga_idx(p - 40);
        } else if (p >= 90 && p <= 97) {
            st->fg = ansi_to_vga_idx(p - 90) | 0x8u;
        } else if (p >= 100 && p <= 107) {
            st->bg = ansi_to_vga_idx(p - 100) | 0x8u;
        }
    }
}

static int console_esc_param_or(console_state_t *st, int idx, int defv) {
    if (!st || idx < 0) return defv;
    if (idx < st->esc_param_count) {
        int v = st->esc_params[idx];
        return v == 0 ? defv : v;
    }
    if (idx == st->esc_param_count && st->esc_cur >= 0) {
        int v = st->esc_cur;
        return v == 0 ? defv : v;
    }
    return defv;
}

static int console_esc_first_param(console_state_t *st, int defv) {
    if (!st) return defv;
    if (st->esc_param_count > 0) return st->esc_params[0];
    if (st->esc_cur >= 0) return st->esc_cur;
    return defv;
}

static void console_esc_reset(console_state_t *st) {
    if (!st) return;
    st->esc_state = 0;
    st->esc_qmark = 0;
    st->esc_bang = 0;
    st->esc_param_count = 0;
    st->esc_cur = -1;
}

static int console_utf8_emit(console_state_t *st, char *ch) {
    unsigned char b = (unsigned char)*ch;
    if (st->utf8_remaining > 0) {
        if ((b & 0xC0u) != 0x80u) {
            st->utf8_remaining = 0;
            st->utf8_code = 0;
            *ch = '?';
            return 1;
        }
        st->utf8_code = (st->utf8_code << 6) | (uint32_t)(b & 0x3Fu);
        if (--st->utf8_remaining != 0) return 0;
        if ((st->utf8_code >= 0x2580u && st->utf8_code <= 0x259Fu) ||
            (st->utf8_code >= 0x25A0u && st->utf8_code <= 0x25FFu)) {
            *ch = '#';
        } else if (st->utf8_code >= 0x2500u && st->utf8_code <= 0x257Fu) {
            *ch = '+';
        } else {
            *ch = '?';
        }
        st->utf8_code = 0;
        return 1;
    }
    if (b < 0x80u) return 1;
    if ((b & 0xE0u) == 0xC0u) {
        st->utf8_code = (uint32_t)(b & 0x1Fu);
        st->utf8_remaining = 1;
        return 0;
    }
    if ((b & 0xF0u) == 0xE0u) {
        st->utf8_code = (uint32_t)(b & 0x0Fu);
        st->utf8_remaining = 2;
        return 0;
    }
    if ((b & 0xF8u) == 0xF0u) {
        st->utf8_code = (uint32_t)(b & 0x07u);
        st->utf8_remaining = 3;
        return 0;
    }
    *ch = '?';
    return 1;
}

static void console_putchar_internal(int vt, char ch) {
    console_state_t *st = console_state_for_vt(vt);
    if (!st) return;
    if (!console_utf8_emit(st, &ch)) return;
    if (st->esc_state == 0) {
        if ((unsigned char)ch == 0x1B) {
            st->esc_state = 1;
            return;
        }
        console_emit_raw_vt(vt, ch, st->fg, st->bg);
        return;
    }
    if (st->esc_state == 1) {
        if (ch == '[') {
            st->esc_state = 2;
            st->esc_qmark = 0;
            st->esc_bang = 0;
            st->esc_param_count = 0;
            st->esc_cur = -1;
            return;
        }
        if (ch == ']') {
            st->esc_state = 4;
            return;
        }
        if (ch == '7') {
            console_get_cursor_vt(vt, &st->saved_col, &st->saved_row);
            console_esc_reset(st);
            return;
        }
        if (ch == '8') {
            console_move_cursor_vt(vt, (uint16_t)st->saved_col, (uint16_t)st->saved_row);
            console_esc_reset(st);
            return;
        }
        if (ch == 'M') {
            console_reverse_index_vt(vt, st->bg);
            console_esc_reset(st);
            return;
        }
        if (ch == 'D' || ch == 'E') {
            int x;
            int y;
            console_get_cursor_vt(vt, &x, &y);
            console_emit_raw_vt(vt, '\n', st->fg, st->bg);
            if (ch == 'D') {
                console_get_cursor_vt(vt, 0, &y);
                console_move_cursor_vt(vt, (uint16_t)x, (uint16_t)y);
            }
            console_esc_reset(st);
            return;
        }
        if (ch == '(' || ch == ')' || ch == '*' || ch == '+') {
            st->esc_state = 3;
            return;
        }
        console_emit_raw_vt(vt, (char)0x1B, st->fg, st->bg);
        console_emit_raw_vt(vt, ch, st->fg, st->bg);
        console_esc_reset(st);
        return;
    }
    if (st->esc_state == 3) {
        console_esc_reset(st);
        return;
    }
    if (st->esc_state == 4) {
        if ((unsigned char)ch == 0x07) {
            console_esc_reset(st);
        } else if ((unsigned char)ch == 0x1B) {
            st->esc_state = 5;
        }
        return;
    }
    if (st->esc_state == 5) {
        if (ch == '\\' || (unsigned char)ch == 0x07) {
            console_esc_reset(st);
        } else if ((unsigned char)ch != 0x1B) {
            st->esc_state = 4;
        }
        return;
    }
    if (st->esc_state != 2) {
        console_esc_reset(st);
        return;
    }
    if (ch == '?') {
        st->esc_qmark = 1;
        return;
    }
    if (ch == '!') {
        st->esc_bang = 1;
        return;
    }
    if (ch >= '0' && ch <= '9') {
        if (st->esc_cur < 0) st->esc_cur = 0;
        st->esc_cur = st->esc_cur * 10 + (ch - '0');
        return;
    }
    if (ch == ';') {
        if (st->esc_param_count < (int)(sizeof(st->esc_params) / sizeof(st->esc_params[0]))) {
            st->esc_params[st->esc_param_count++] = (st->esc_cur < 0) ? 0 : st->esc_cur;
        }
        st->esc_cur = -1;
        return;
    }
    if (ch == 'm') {
        console_apply_sgr(st);
        console_esc_reset(st);
        return;
    }
    if (ch == 'p' && st->esc_bang) {
        st->fg = st->default_fg;
        st->bg = st->default_bg;
        st->utf8_code = 0;
        st->utf8_remaining = 0;
        console_esc_reset(st);
        return;
    }
    if (ch == 'H' || ch == 'f') {
        int row = console_esc_param_or(st, 0, 1);
        int col = console_esc_param_or(st, 1, 1);
        if (row < 1) row = 1;
        if (col < 1) col = 1;
        if (row > console_rows()) row = console_rows();
        if (col > console_cols()) col = console_cols();
        console_move_cursor_vt(vt, (uint16_t)(col - 1), (uint16_t)(row - 1));
        console_esc_reset(st);
        return;
    }
    if (ch == 'G') {
        int col = console_esc_param_or(st, 0, 1);
        int x, y;
        if (col < 1) col = 1;
        if (col > console_cols()) col = console_cols();
        console_get_cursor_vt(vt, &x, &y);
        console_move_cursor_vt(vt, (uint16_t)(col - 1), (uint16_t)y);
        console_esc_reset(st);
        return;
    }
    if (ch == 'd') {
        int row = console_esc_param_or(st, 0, 1);
        int x, y;
        if (row < 1) row = 1;
        if (row > console_rows()) row = console_rows();
        console_get_cursor_vt(vt, &x, &y);
        console_move_cursor_vt(vt, (uint16_t)x, (uint16_t)(row - 1));
        console_esc_reset(st);
        return;
    }
    if (ch == 'A' || ch == 'B' || ch == 'C' || ch == 'D') {
        int n = console_esc_first_param(st, 1);
        int x, y;
        int cols = console_cols();
        int rows = console_rows();
        if (n < 1) n = 1;
        console_get_cursor_vt(vt, &x, &y);
        if (ch == 'A') y -= n;
        else if (ch == 'B') y += n;
        else if (ch == 'C') x += n;
        else x -= n;
        if (x < 0) x = 0;
        if (y < 0) y = 0;
        if (x >= cols) x = cols - 1;
        if (y >= rows) y = rows - 1;
        console_move_cursor_vt(vt, (uint16_t)x, (uint16_t)y);
        console_esc_reset(st);
        return;
    }
    if (ch == 'J') {
        console_erase_in_display_vt(vt, st, console_esc_first_param(st, 0));
        console_esc_reset(st);
        return;
    }
    if (ch == 'K') {
        console_erase_in_line_vt(vt, console_esc_first_param(st, 0), st->fg, st->bg);
        console_esc_reset(st);
        return;
    }
    if (ch == 'P' || ch == 'X') {
        int n = console_esc_first_param(st, 1);
        if (n < 1) n = 1;
        console_erase_chars_at_cursor_vt(vt, st, n);
        console_esc_reset(st);
        return;
    }
    if (ch == 's') {
        console_get_cursor_vt(vt, &st->saved_col, &st->saved_row);
        console_esc_reset(st);
        return;
    }
    if (ch == 'u') {
        console_move_cursor_vt(vt, (uint16_t)st->saved_col, (uint16_t)st->saved_row);
        console_esc_reset(st);
        return;
    }
    if ((ch == 'h' || ch == 'l') && st->esc_qmark) {
        if (st->esc_cur == 25) {
            console_esc_reset(st);
            return;
        }
        if (st->esc_cur == 7 || st->esc_cur == 47 || st->esc_cur == 1047 || st->esc_cur == 1048 || st->esc_cur == 1049) {
            if (st->esc_cur == 1049 && ch == 'h') {
                console_get_cursor_vt(vt, &st->saved_col, &st->saved_row);
                console_clear_vt_internal(vt, st->default_fg, st->default_bg);
            } else if (st->esc_cur == 1049 && ch == 'l') {
                console_clear_vt_internal(vt, st->default_fg, st->default_bg);
                console_move_cursor_vt(vt, (uint16_t)st->saved_col, (uint16_t)st->saved_row);
            }
            console_esc_reset(st);
            return;
        }
    }
    if (ch == 'r') {
        console_esc_reset(st);
        return;
    }
    console_esc_reset(st);
}

// ===== Backend selection =====
void console_set_backend(const console_backend_t* be) { g_be = be; }

// ===== Basic console control =====
void console_init(uint32_t fore_color, uint32_t back_color) {
    if (g_be && g_be->init) g_be->init(fore_color, back_color);
    for (int vt = 1; vt <= EDGE_FB_VT_COUNT; ++vt) {
        console_reset_vt_state(vt, fore_color, back_color);
    }
    if (console_is_fb_backend()) {
        /*
         * Reset all framebuffer VT cell stores once, after the backend has
         * established its geometry, and publish one final clean frame.
         */
        fb_console_reset_all_vts(back_color);
    } else {
        /*
         * Text backends expose one visible buffer even though the common ANSI
         * parser retains state for every Linux VT.
         */
        if (g_be && g_be->set_color)
            g_be->set_color(fore_color, back_color);
        if (g_be && g_be->clear) g_be->clear();
    }
}

void console_clear(uint32_t fore_color, uint32_t back_color) {
    console_clear_vt_internal(console_current_vt(), fore_color, back_color);
}

void console_activate_vt(int vt) {
    vt = console_clamp_vt(vt);
    if (console_is_fb_backend()) fb_console_activate_vt(vt);
}

int console_get_active_vt(void) {
    return console_current_vt();
}

void console_putchar_vt(int vt, char ch) {
    console_putchar_internal(console_clamp_vt(vt), ch);
    if (console_is_fb_backend() &&
        __atomic_load_n(&g_console_output_batch_depth, __ATOMIC_ACQUIRE) == 0)
        fb_console_request_present();
}

void console_putchar(char ch) {
    serial_console_write_raw(ch);
    /*
     * When Xorg owns /dev/fb0 through mmap, Linux leaves kernel/user console
     * text on the backing VT instead of scribbling over the active scanout.
     * EdgeOS' fb console renderer shares the same physical framebuffer, so
     * emitting every debug byte to the framebuffer while X is repainting can
     * corrupt the display path and stall desktop startup.  Keep serial as the
     * primary debug console, per AGENTS.md, and suppress fb-console rendering
     * while userspace owns fbdev.
     */
    if (fb_user_mmap_active()) return;
    console_putchar_internal(console_current_vt(), ch);
    if (console_is_fb_backend() &&
        __atomic_load_n(&g_console_output_batch_depth, __ATOMIC_ACQUIRE) == 0)
        fb_console_request_present();
}

void console_output_batch_begin(void) {
    __atomic_add_fetch(&g_console_output_batch_depth, 1u, __ATOMIC_ACQ_REL);
}

void console_output_batch_end(void) {
    unsigned int depth;

    depth = __atomic_load_n(&g_console_output_batch_depth, __ATOMIC_ACQUIRE);
    if (depth == 0) return;
    depth = __atomic_sub_fetch(
        &g_console_output_batch_depth, 1u, __ATOMIC_ACQ_REL);
    if (depth == 0 && console_is_fb_backend())
        fb_console_request_present();
}

void console_putstr(const char *str) {
    if (!str) return;
    console_output_batch_begin();
    while (*str) console_putchar(*str++);
    console_output_batch_end();
}

static void console_kernel_log_putchar(char ch) {
    if (EDGE_KERNEL_DEFAULT_MESSAGE_LOGLEVEL >=
        __atomic_load_n(&g_kernel_console_loglevel, __ATOMIC_RELAXED))
        return;
    if (edge_linux_tty_console_redirect_emit(ch)) {
        /* Keep the independently registered serial debug console observable. */
        serial_console_write_raw(ch);
        return;
    }
    console_putchar(ch);
}

void console_kernel_log_putstr(const char *str) {
    if (!str) return;
    while (*str) console_kernel_log_putchar(*str++);
}

void console_kernel_log_off(void) {
    int current = __atomic_load_n(
        &g_kernel_console_loglevel, __ATOMIC_RELAXED);
    int expected = -1;
    (void)__atomic_compare_exchange_n(
        &g_kernel_saved_console_loglevel, &expected, current, 0,
        __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    __atomic_store_n(&g_kernel_console_loglevel,
                     EDGE_KERNEL_MINIMUM_CONSOLE_LOGLEVEL,
                     __ATOMIC_RELAXED);
}

void console_kernel_log_on(void) {
    int saved = __atomic_exchange_n(
        &g_kernel_saved_console_loglevel, -1, __ATOMIC_RELAXED);
    if (saved >= EDGE_KERNEL_MINIMUM_CONSOLE_LOGLEVEL)
        __atomic_store_n(&g_kernel_console_loglevel, saved,
                         __ATOMIC_RELAXED);
}

int console_kernel_log_set_level(int level) {
    if (level < 1 || level > 8) return -1;
    if (level < EDGE_KERNEL_MINIMUM_CONSOLE_LOGLEVEL)
        level = EDGE_KERNEL_MINIMUM_CONSOLE_LOGLEVEL;
    __atomic_store_n(&g_kernel_console_loglevel, level,
                     __ATOMIC_RELAXED);
    return 0;
}

void console_gotoxy(uint16_t x, uint16_t y) {
    console_move_cursor_vt(console_current_vt(), x, y);
}

void console_ungetchar(void) {
    console_putchar('\b');
}

void console_ungetchar_bound(uint8_t n) {
    while (n--) console_ungetchar();
}

extern void itoa(char *buf, int base, int d);

static int console_uint_to_str(char *buf, uint64_t v, int base) {
    static const char digits[] = "0123456789abcdef";
    char tmp[32];
    int n = 0;
    int out = 0;
    if (!buf) return 0;
    if (base < 2 || base > 16) base = 10;
    if (v == 0) tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = digits[v % (uint64_t)base];
        v /= (uint64_t)base;
    }
    while (n > 0) buf[out++] = tmp[--n];
    buf[out] = 0;
    return out;
}

static int console_int_to_str(char *buf, int64_t v) {
    if (!buf) return 0;
    if (v < 0) {
        buf[0] = '-';
        return 1 + console_uint_to_str(buf + 1, (uint64_t)(-v), 10);
    }
    return console_uint_to_str(buf, (uint64_t)v, 10);
}

void console_set_kernel_log_timestamps(int enabled) {
    g_kernel_log_timestamps = enabled ? 1 : 0;
    g_kernel_log_at_line_start = 1;
    g_kernel_log_line_len = 0;
}

static void printf_log_record_char(char ch) {
    if (!g_kernel_log_timestamps) return;
    if (g_kernel_log_line_len + 1u < sizeof(g_kernel_log_line)) {
        g_kernel_log_line[g_kernel_log_line_len++] = ch;
    }
    if (ch == '\n') {
        bootlog_append_raw(g_kernel_log_line, g_kernel_log_line_len);
        g_kernel_log_line_len = 0;
    }
}

static void printf_emit_timestamp_if_needed(char ch) {
    char prefix[32];
    int n;

    if (!g_kernel_log_timestamps || !g_kernel_log_at_line_start || ch == '\n' || ch == '\r') return;
    n = bootlog_format_timestamp_prefix(prefix, sizeof(prefix));
    if (n <= 0) return;
    for (int i = 0; i < n; ++i) {
        console_kernel_log_putchar(prefix[i]);
        printf_log_record_char(prefix[i]);
    }
    g_kernel_log_at_line_start = 0;
}

static void printf_emit_char(char ch) {
    printf_emit_timestamp_if_needed(ch);
    console_kernel_log_putchar(ch);
    printf_log_record_char(ch);
    if (g_kernel_log_timestamps && ch == '\n') g_kernel_log_at_line_start = 1;
}

static void printf_emit_str(const char *s) {
    if (!s) s = "";
    while (*s) printf_emit_char(*s++);
}

static void printf_emit_padded(const char *s, int pad, int pad0) {
    int n = s ? strlen(s) : 0;
    for (int i = n; i < pad; ++i) printf_emit_char(pad0 ? '0' : ' ');
    printf_emit_str(s ? s : "");
}

static void vprintf_core(uint32_t color, const char *format, va_list ap) {
    int vt = console_current_vt();
    console_state_t *st = console_state_for_vt(vt);
    uint32_t old_fg = st->fg;
    int c;
    char buf[64];

    st->fg = color;
    while ((c = *format++) != 0) {
        if (c != '%') {
            printf_emit_char((char)c);
            continue;
        }

        {
            int pad0 = 0, pad = 0;
            int long_count = 0;
            int size_t_arg = 0;
            c = *format++;
            if (c == '0') { pad0 = 1; c = *format++; }
            while (c >= '0' && c <= '9') {
                pad = pad * 10 + (c - '0');
                c = *format++;
            }
            while (c == 'l') {
                long_count++;
                c = *format++;
            }
            if (c == 'z') {
                size_t_arg = 1;
                c = *format++;
            }

            switch (c) {
            case 'd': {
                int64_t v;
                memset(buf, 0, sizeof(buf));
                if (size_t_arg) v = (int64_t)va_arg(ap, size_t);
                else if (long_count >= 2) v = va_arg(ap, long long);
                else if (long_count == 1) v = va_arg(ap, long);
                else v = va_arg(ap, int);
                console_int_to_str(buf, v);
                printf_emit_padded(buf, pad, pad0);
                break;
            }
            case 'u':
            case 'x':
            case 'o': {
                uint64_t v;
                int base = (c == 'x') ? 16 : (c == 'o' ? 8 : 10);
                memset(buf, 0, sizeof(buf));
                if (size_t_arg) v = (uint64_t)va_arg(ap, size_t);
                else if (long_count >= 2) v = va_arg(ap, unsigned long long);
                else if (long_count == 1) v = va_arg(ap, unsigned long);
                else v = va_arg(ap, unsigned int);
                console_uint_to_str(buf, v, base);
                printf_emit_padded(buf, pad, pad0);
                break;
            }
            case 'p': {
                uint64_t v = (uint64_t)(uintptr_t)va_arg(ap, void *);
                memset(buf, 0, sizeof(buf));
                buf[0] = '0';
                buf[1] = 'x';
                console_uint_to_str(buf + 2, v, 16);
                printf_emit_padded(buf, pad, pad0);
                break;
            }
            case 's': {
                const char *p = va_arg(ap, const char*);
                if (!p) p = "(null)";
                printf_emit_padded(p, pad, pad0);
                break;
            }
            case 'c':
                printf_emit_char((char)va_arg(ap, int));
                break;
            case '%':
                printf_emit_char('%');
                break;
            default:
                printf_emit_char('%');
                printf_emit_char((char)c);
                break;
            }
        }
    }
    st->fg = old_fg;
}

void printf(const char *format, ...) {
    uint64_t flags;
    va_list ap;
    /*
     * printf is used from exception paths.  If a user fault interrupts a kernel
     * path already holding the console formatter lock, spinning here prevents
     * the trap handler from killing the faulting task and can pin the whole VM.
     * Linux keeps printk re-entrant enough for oops paths; EdgeOS' minimal
     * console should drop a nested diagnostic line rather than deadlock.
     */
    if (!spin_trylock_irqsave(&g_printf_lock, &flags)) return;
    console_output_batch_begin();
    va_start(ap, format);
    vprintf_core(0xFFFFFFFF, format, ap);
    va_end(ap);
    console_output_batch_end();
    spin_unlock_irqrestore(&g_printf_lock, flags);
}

void printf_color(uint32_t color, const char *format, ...) {
    uint64_t flags;
    va_list ap;
    if (!spin_trylock_irqsave(&g_printf_lock, &flags)) return;
    console_output_batch_begin();
    va_start(ap, format);
    vprintf_core(color, format, ap);
    va_end(ap);
    console_output_batch_end();
    spin_unlock_irqrestore(&g_printf_lock, flags);
}

void getstr(char *buffer) {
    if (!buffer) return;
    {
        uint32_t i = 0;
        for (;;) {
            char ch = kb_getchar();
            if (ch == '\n') { console_putchar('\n'); buffer[i] = '\0'; return; }
            if (ch == '\b') {
                if (i > 0) { --i; console_ungetchar(); }
                continue;
            }
            buffer[i++] = ch;
            console_putchar(ch);
        }
    }
}

void getstr_bound(char *buffer, uint8_t bound) {
    if (!buffer || bound == 0) return;
    {
        uint32_t i = 0;
        for (;;) {
            char ch = kb_getchar();
            if (ch == '\n') { console_putchar('\n'); buffer[i] = '\0'; return; }
            if (ch == '\b') {
                if (i > 0) { --i; console_ungetchar(); }
                continue;
            }
            if (i + 1 < bound) {
                buffer[i++] = ch;
                console_putchar(ch);
            }
        }
    }
}

uint8_t get_cursor_x(void) {
    int x = 0;
    console_get_cursor_vt(console_current_vt(), &x, 0);
    if (x < 0) x = 0;
    if (x > 255) x = 255;
    return (uint8_t)x;
}

uint8_t get_cursor_y(void) {
    int y = 0;
    console_get_cursor_vt(console_current_vt(), 0, &y);
    if (y < 0) y = 0;
    if (y > 255) y = 255;
    return (uint8_t)y;
}
