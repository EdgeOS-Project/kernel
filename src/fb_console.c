#include "fb_console.h"
#include "kernel/timer_policy.h"
#include "display.h"
#include "fb.h"
#include "font8x8_basic.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

enum { EDGE_FB_FONT_MAX_GLYPHS = 512, EDGE_FB_FONT_MAX_HEIGHT = 32 };
enum { EDGE_FB_MAX_COLS = 160, EDGE_FB_MAX_ROWS = 100 };

typedef struct {
    unsigned char ch;
    uint8_t fg;
    uint8_t bg;
} fb_vt_cell_t;

typedef struct {
    int cur_col;
    int cur_row;
    fb_vt_cell_t cells[EDGE_FB_MAX_COLS * EDGE_FB_MAX_ROWS];
} fb_vt_state_t;

static fb_vt_state_t g_vts[EDGE_FB_VT_COUNT];
static int g_active_vt = 1;
static int cols, rows;
static int cursor_enabled, cursor_visible;
static uint32_t last_blink_tick;
static int dirty;
static int dirty_full;
static int dirty_x0, dirty_y0, dirty_x1, dirty_y1;
static int present_enabled = 1;
static int present_requested = 1;
static int fbdev_owned;
static int drm_owned;
static spinlock_t console_lock;
static volatile int deferred_present_pending;
static volatile int deferred_tick_pending;
static volatile uint32_t deferred_ticks;
static volatile uint64_t deferred_present_first_us;
static volatile uint64_t deferred_present_last_us;
static uint8_t g_font_data[EDGE_FB_FONT_MAX_GLYPHS * EDGE_FB_FONT_MAX_HEIGHT];
static uint32_t g_font_charcount;
static uint32_t g_font_width;
static uint32_t g_font_height;
static uint32_t g_font_scale;
static int g_font_user_loaded;

#define FB_CONSOLE_PRESENT_IDLE_US 20000ull
#define FB_CONSOLE_PRESENT_MAX_LATENCY_US 100000ull

static int font_pixel_w(void) { return (int)(g_font_width * g_font_scale); }
static int font_pixel_h(void) { return (int)(g_font_height * g_font_scale); }
static int cell_w(void){ return font_pixel_w() + 1; }
static int cell_h(void){ return font_pixel_h() + 2; }
static int col_x(int c){ return c * cell_w(); }
static int row_y(int r){ return r * cell_h(); }

static uint32_t vga_rgb(uint32_t idx) {
    static const uint32_t lut[16] = {
        0xFF000000,0xFF0000AA,0xFF00AA00,0xFF00AAAA,0xFFAA0000,0xFFAA00AA,0xFFAA5500,0xFFAAAAAA,
        0xFF555555,0xFF5555FF,0xFF55FF55,0xFF55FFFF,0xFFFF5555,0xFFFF55FF,0xFFFFFF55,0xFFFFFFFF
    };
    return lut[idx & 0x0F];
}

static void mark_dirty_rect(int x, int y, int w, int h) {
    int x1;
    int y1;
    if (w <= 0 || h <= 0) return;
    if (x < 0) {
        w += x;
        x = 0;
    }
    if (y < 0) {
        h += y;
        y = 0;
    }
    if (x >= (int)fb.width || y >= (int)fb.height || w <= 0 || h <= 0) return;
    x1 = x + w;
    y1 = y + h;
    if (x1 > (int)fb.width) x1 = (int)fb.width;
    if (y1 > (int)fb.height) y1 = (int)fb.height;
    if (!dirty) {
        dirty_x0 = x;
        dirty_y0 = y;
        dirty_x1 = x1;
        dirty_y1 = y1;
    } else {
        if (x < dirty_x0) dirty_x0 = x;
        if (y < dirty_y0) dirty_y0 = y;
        if (x1 > dirty_x1) dirty_x1 = x1;
        if (y1 > dirty_y1) dirty_y1 = y1;
    }
    dirty = 1;
}

static void mark_dirty_cell(int col, int row) {
    mark_dirty_rect(col_x(col), row_y(row), cell_w(), cell_h());
}

static void mark_dirty_full(void) {
    dirty = 1;
    dirty_full = 1;
    dirty_x0 = 0;
    dirty_y0 = 0;
    dirty_x1 = (int)fb.width;
    dirty_y1 = (int)fb.height;
}

static int vt_index(int vt) {
    if (vt < 1 || vt > EDGE_FB_VT_COUNT) return -1;
    return vt - 1;
}

static fb_vt_state_t *vt_state(int vt) {
    int idx = vt_index(vt);
    if (idx < 0) return 0;
    return &g_vts[idx];
}

static fb_vt_cell_t *vt_cell_at(fb_vt_state_t *st, int col, int row) {
    if (!st || col < 0 || row < 0 || col >= cols || row >= rows) return 0;
    return &st->cells[row * EDGE_FB_MAX_COLS + col];
}

static uint8_t reverse_bits8(uint8_t v) {
    v = (uint8_t)(((v & 0x55u) << 1) | ((v & 0xAAu) >> 1));
    v = (uint8_t)(((v & 0x33u) << 2) | ((v & 0xCCu) >> 2));
    return (uint8_t)((v << 4) | (v >> 4));
}

static void fb_console_load_default_font(void) {
    memset(g_font_data, 0, sizeof(g_font_data));
    for (uint32_t ch = 0; ch < 128u; ++ch) {
        for (uint32_t row = 0; row < 8u; ++row) {
            g_font_data[ch * EDGE_FB_FONT_MAX_HEIGHT + row] = reverse_bits8(font8x8_basic[ch][row]);
        }
    }
    g_font_charcount = 256;
    g_font_width = 8;
    g_font_height = 8;
    g_font_user_loaded = 0;
}

static void fb_console_recompute_geometry(void) {
    uint32_t scale = 1;

    if (!g_font_width || !g_font_height) fb_console_load_default_font();
    /*
     * Keep explicit setfont sizes exact.  For the built-in boot font, scale on
     * large framebuffers so 1080p/HiDPI VM and laptop consoles do not start as
     * tiny 8x8 text.  This mirrors the BSD vt/syscons idea of deriving the text
     * grid from active font metrics while preserving Linux setfont semantics.
     */
    if (!g_font_user_loaded && fb.width >= 1600u && fb.height >= 900u) scale = 2;
    g_font_scale = scale;
    cols = (int)(fb.width / (uint32_t)cell_w());
    rows = (int)(fb.height / (uint32_t)cell_h());
    if (cols < 1) cols = 1;
    if (rows < 1) rows = 1;
    if (cols > EDGE_FB_MAX_COLS) cols = EDGE_FB_MAX_COLS;
    if (rows > EDGE_FB_MAX_ROWS) rows = EDGE_FB_MAX_ROWS;
    for (int vt = 1; vt <= EDGE_FB_VT_COUNT; ++vt) {
        fb_vt_state_t *st = vt_state(vt);
        if (!st) continue;
        if (st->cur_col >= cols) st->cur_col = cols - 1;
        if (st->cur_row >= rows) st->cur_row = rows - 1;
    }
}

static void draw_cell(int col, int row, unsigned char ch, uint32_t fg, uint32_t bg) {
    int x = col_x(col), y = row_y(row);
    uint32_t glyph = (uint32_t)ch;
    if (glyph >= g_font_charcount) glyph = (uint32_t)'?';
    for (uint32_t ry = 0; ry < g_font_height; ry++) {
        uint8_t bits = g_font_data[glyph * EDGE_FB_FONT_MAX_HEIGHT + ry];
        for (uint32_t cx = 0; cx < g_font_width; cx++) {
            uint32_t color = (bits & (uint8_t)(0x80u >> cx)) ? fg : bg;
            for (uint32_t sy = 0; sy < g_font_scale; ++sy) {
                for (uint32_t sx = 0; sx < g_font_scale; ++sx) {
                    fb_putpixel(x + (int)(cx * g_font_scale + sx),
                                y + (int)(ry * g_font_scale + sy),
                                color);
                }
            }
        }
    }
    for (int ry = font_pixel_h(); ry < cell_h(); ry++) {
        for (int cx = 0; cx < font_pixel_w(); cx++) fb_putpixel(x + cx, y + ry, bg);
    }
    for (int ry = 0; ry < cell_h(); ry++) fb_putpixel(x + font_pixel_w(), y + ry, bg);
}

static void draw_cursor(void) {
    fb_vt_state_t *st = vt_state(g_active_vt);
    int x, y;
    if (!st || !cursor_enabled || !cursor_visible) return;
    x = col_x(st->cur_col);
    y = row_y(st->cur_row) + font_pixel_h() - 1;
    for (int cx = 0; cx < font_pixel_w(); ++cx) fb_putpixel(x + cx, y, vga_rgb(15));
    mark_dirty_rect(x, y, font_pixel_w(), 1);
}

static void erase_cursor(void) {
    fb_vt_state_t *st = vt_state(g_active_vt);
    fb_vt_cell_t *cell;
    int x, y;
    if (!st || !cursor_enabled || !cursor_visible) return;
    cell = vt_cell_at(st, st->cur_col, st->cur_row);
    if (!cell) return;
    x = col_x(st->cur_col);
    y = row_y(st->cur_row) + font_pixel_h() - 1;
    for (int cx = 0; cx < font_pixel_w(); ++cx) fb_putpixel(x + cx, y, vga_rgb(cell->bg));
    mark_dirty_rect(x, y, font_pixel_w(), 1);
}

static void vt_fill_blank(fb_vt_state_t *st, int col, int row, uint8_t bg) {
    fb_vt_cell_t *cell = vt_cell_at(st, col, row);
    if (!cell) return;
    cell->ch = ' ';
    cell->fg = 15;
    cell->bg = bg;
}

static void vt_redraw(int vt) {
    fb_vt_state_t *st = vt_state(vt);
    if (!st) return;
    for (int row = 0; row < rows; ++row) {
        for (int col = 0; col < cols; ++col) {
            fb_vt_cell_t *cell = vt_cell_at(st, col, row);
            if (!cell) continue;
            draw_cell(col, row, cell->ch, vga_rgb(cell->fg), vga_rgb(cell->bg));
        }
    }
    draw_cursor();
    mark_dirty_full();
}

static void vt_scroll_visible_pixels(uint8_t bg) {
    uint8_t *base = fb_get_draw_buffer();
    int scroll_px = cell_h();
    int text_h = rows * cell_h();
    uint32_t bg_argb = vga_rgb(bg);
    if (!base || scroll_px <= 0 || text_h <= scroll_px) return;

    /*
     * Scrolling used to redraw every cell after every newline at the bottom of
     * the screen. Mirroring serial console output into the framebuffer makes
     * OpenRC produce many scrolls, so full glyph redraws here can slow init
     * enough that getty appears missing. Move the rendered pixels and clear
     * only the newly exposed line; the cell array is moved separately below.
     */
    memmove(base, base + (uint32_t)scroll_px * fb.pitch, (uint32_t)(text_h - scroll_px) * fb.pitch);
    for (int y = text_h - scroll_px; y < text_h; ++y) {
        for (uint32_t x = 0; x < fb.width; ++x) {
            fb_putpixel((int)x, y, bg_argb);
        }
    }
    mark_dirty_full();
}

static void vt_scroll_visible_pixels_down(uint8_t bg) {
    uint8_t *base = fb_get_draw_buffer();
    int scroll_px = cell_h();
    int text_h = rows * cell_h();
    uint32_t bg_argb = vga_rgb(bg);
    if (!base || scroll_px <= 0 || text_h <= scroll_px) return;

    memmove(base + (uint32_t)scroll_px * fb.pitch, base,
            (uint32_t)(text_h - scroll_px) * fb.pitch);
    for (int y = 0; y < scroll_px; ++y) {
        for (uint32_t x = 0; x < fb.width; ++x)
            fb_putpixel((int)x, y, bg_argb);
    }
    mark_dirty_full();
}

static void vt_scroll_up_one_row(int vt, uint8_t bg) {
    fb_vt_state_t *st = vt_state(vt);
    if (!st || rows <= 1) return;
    memmove(st->cells, st->cells + EDGE_FB_MAX_COLS, (size_t)(rows - 1) * EDGE_FB_MAX_COLS * sizeof(fb_vt_cell_t));
    for (int col = 0; col < cols; ++col) vt_fill_blank(st, col, rows - 1, bg);
    if (vt == g_active_vt && present_enabled) vt_scroll_visible_pixels(bg);
}

static void vt_scroll_down_one_row(int vt, uint8_t bg) {
    fb_vt_state_t *st = vt_state(vt);
    if (!st || rows <= 1) return;
    memmove(st->cells + EDGE_FB_MAX_COLS, st->cells,
            (size_t)(rows - 1) * EDGE_FB_MAX_COLS *
                sizeof(fb_vt_cell_t));
    for (int col = 0; col < cols; ++col) vt_fill_blank(st, col, 0, bg);
    if (vt == g_active_vt && present_enabled)
        vt_scroll_visible_pixels_down(bg);
}

static void vt_reverse_index_internal(int vt, uint8_t bg) {
    fb_vt_state_t *st = vt_state(vt);
    int visible;
    if (!st) return;
    visible = vt == g_active_vt && present_enabled;
    if (visible) erase_cursor();
    if (st->cur_row > 0)
        --st->cur_row;
    else
        vt_scroll_down_one_row(vt, bg);
    if (visible) draw_cursor();
}

static void vt_newline(int vt, uint8_t bg) {
    fb_vt_state_t *st = vt_state(vt);
    if (!st) return;
    st->cur_col = 0;
    st->cur_row++;
    if (st->cur_row >= rows) {
        st->cur_row = rows - 1;
        vt_scroll_up_one_row(vt, bg);
    }
}

static void vt_clear_internal(int vt, uint8_t bg) {
    fb_vt_state_t *st = vt_state(vt);
    if (!st) return;
    st->cur_col = 0;
    st->cur_row = 0;
    for (int row = 0; row < rows; ++row) {
        for (int col = 0; col < cols; ++col) vt_fill_blank(st, col, row, bg);
    }
    if (vt == g_active_vt && present_enabled) {
        fb_clear(vga_rgb(bg));
        draw_cursor();
        mark_dirty_full();
    }
}

static void vt_putchar_internal(int vt, char ch, uint8_t fg, uint8_t bg) {
    fb_vt_state_t *st = vt_state(vt);
    fb_vt_cell_t *cell;
    int visible;
    if (!st) return;
    visible = (vt == g_active_vt && present_enabled);
    if (visible) erase_cursor();
    if (ch == '\n') {
        vt_newline(vt, bg);
    } else if (ch == '\r') {
        st->cur_col = 0;
    } else if (ch == '\b') {
        if (st->cur_col > 0) st->cur_col--;
    } else {
        cell = vt_cell_at(st, st->cur_col, st->cur_row);
        if (cell) {
            cell->ch = (unsigned char)ch;
            cell->fg = fg;
            cell->bg = bg;
            if (visible) draw_cell(st->cur_col, st->cur_row, cell->ch, vga_rgb(fg), vga_rgb(bg));
            if (visible) mark_dirty_cell(st->cur_col, st->cur_row);
        }
        st->cur_col++;
        if (st->cur_col >= cols) vt_newline(vt, bg);
    }
    if (visible) {
        draw_cursor();
    }
}

static void vt_move_cursor_internal(int vt, int x, int y) {
    fb_vt_state_t *st = vt_state(vt);
    int visible;
    if (!st) return;
    visible = (vt == g_active_vt && present_enabled);
    if (visible) erase_cursor();
    if (x >= 0 && x < cols) st->cur_col = x;
    if (y >= 0 && y < rows) st->cur_row = y;
    if (visible) {
        draw_cursor();
    }
}

static void vt_erase_in_line_internal(int vt, int mode, uint8_t bg) {
    fb_vt_state_t *st = vt_state(vt);
    int start = 0;
    int end = cols - 1;
    int visible;
    if (!st) return;
    visible = (vt == g_active_vt && present_enabled);
    if (mode == 0) start = st->cur_col;
    else if (mode == 1) end = st->cur_col;
    else if (mode != 2) return;
    if (visible) erase_cursor();
    for (int col = start; col <= end; ++col) {
        vt_fill_blank(st, col, st->cur_row, bg);
        if (visible) {
            draw_cell(col, st->cur_row, ' ', vga_rgb(15), vga_rgb(bg));
            mark_dirty_cell(col, st->cur_row);
        }
    }
    if (visible) {
        draw_cursor();
    }
}

static void be_init(uint32_t fg, uint32_t bg) {
    uint64_t flags = spin_lock_irqsave(&console_lock);
    (void)fg;
    (void)bg;
    (void)fb_enable_backbuffer();
    fb_console_load_default_font();
    fb_console_recompute_geometry();
    cursor_enabled = 1;
    cursor_visible = 1;
    last_blink_tick = 0;
    g_active_vt = 1;
    /*
     * The common console layer resets parser state and framebuffer cells
     * together after backend geometry is ready.  Keeping that work out of the
     * backend avoids clearing every virtual terminal twice during boot.
     */
    spin_unlock_irqrestore(&console_lock, flags);
}

static void be_set_color(uint32_t fg, uint32_t bg) { (void)fg; (void)bg; }
static void be_clear(void) {
    uint64_t flags = spin_lock_irqsave(&console_lock);
    vt_clear_internal(g_active_vt, 0);
    spin_unlock_irqrestore(&console_lock, flags);
}
static void be_move_cursor(int x, int y) {
    uint64_t flags = spin_lock_irqsave(&console_lock);
    vt_move_cursor_internal(g_active_vt, x, y);
    spin_unlock_irqrestore(&console_lock, flags);
}
static void be_get_cursor(int *x, int *y) {
    fb_vt_state_t *st = vt_state(g_active_vt);
    if (!st) return;
    if (x) *x = st->cur_col;
    if (y) *y = st->cur_row;
}
static int be_get_cols(void) { return cols; }
static int be_get_rows(void) { return rows; }
static void be_erase_in_line(int mode) {
    uint64_t flags = spin_lock_irqsave(&console_lock);
    vt_erase_in_line_internal(g_active_vt, mode, 0);
    spin_unlock_irqrestore(&console_lock, flags);
}
static void be_putchar(char ch) {
    uint64_t flags = spin_lock_irqsave(&console_lock);
    vt_putchar_internal(g_active_vt, ch, 15, 0);
    spin_unlock_irqrestore(&console_lock, flags);
}

const console_backend_t FB_CONSOLE = {
    be_init,
    be_set_color,
    be_clear,
    be_putchar,
    be_move_cursor,
    be_get_cursor,
    be_get_cols,
    be_get_rows,
    be_erase_in_line
};

static void fb_console_present_locked(void) {
    if (!present_enabled) return;
    if (dirty) {
        if (dirty_full) {
            fb_present();
            if (!display_backend_requires_present())
                fb_flush_rect(0, 0, (int)fb.width, (int)fb.height);
        } else {
            fb_present_rect(dirty_x0, dirty_y0, dirty_x1 - dirty_x0, dirty_y1 - dirty_y0);
            if (!display_backend_requires_present())
                fb_flush_rect(dirty_x0, dirty_y0,
                              dirty_x1 - dirty_x0, dirty_y1 - dirty_y0);
        }
        dirty = 0;
        dirty_full = 0;
    }
}

void fb_console_present(void) {
    uint64_t flags = spin_lock_irqsave(&console_lock);
    fb_console_present_locked();
    spin_unlock_irqrestore(&console_lock, flags);
}

void fb_console_request_present(void) {
    uint64_t now_us;

    if (!display_backend_requires_present()) {
        fb_console_present();
        return;
    }
    now_us = boottime_monotonic_us();
    if (!__atomic_exchange_n(
            &deferred_present_pending, 1, __ATOMIC_ACQ_REL))
        __atomic_store_n(
            &deferred_present_first_us, now_us, __ATOMIC_RELEASE);
    __atomic_store_n(
        &deferred_present_last_us, now_us, __ATOMIC_RELEASE);
}

void fb_console_request_tick_from_irq(uint32_t ticks) {
    __atomic_store_n(&deferred_ticks, ticks, __ATOMIC_RELEASE);
    __atomic_store_n(&deferred_tick_pending, 1, __ATOMIC_RELEASE);
}

void fb_console_pump_deferred(void) {
    uint64_t first_us;
    uint64_t last_us;
    uint64_t now_us;
    uint32_t ticks;

    if (__atomic_exchange_n(
            &deferred_tick_pending, 0, __ATOMIC_ACQ_REL)) {
        ticks = __atomic_load_n(&deferred_ticks, __ATOMIC_ACQUIRE);
        fb_console_tick(ticks);
    }
    if (!__atomic_load_n(
            &deferred_present_pending, __ATOMIC_ACQUIRE))
        return;
    now_us = boottime_monotonic_us();
    first_us = __atomic_load_n(
        &deferred_present_first_us, __ATOMIC_ACQUIRE);
    last_us = __atomic_load_n(
        &deferred_present_last_us, __ATOMIC_ACQUIRE);
    if (first_us <= now_us && last_us <= now_us &&
        now_us - first_us < FB_CONSOLE_PRESENT_MAX_LATENCY_US &&
        now_us - last_us < FB_CONSOLE_PRESENT_IDLE_US)
        return;
    if (!__atomic_exchange_n(
            &deferred_present_pending, 0, __ATOMIC_ACQ_REL))
        return;
    __atomic_store_n(
        &deferred_present_first_us, 0, __ATOMIC_RELEASE);
    __atomic_store_n(
        &deferred_present_last_us, 0, __ATOMIC_RELEASE);
    fb_console_present();
}

void fb_console_reset_all_vts(uint32_t bg) {
    uint64_t flags = spin_lock_irqsave(&console_lock);
    uint8_t background = (uint8_t)(bg & 0x0F);

    for (int vt = 1; vt <= EDGE_FB_VT_COUNT; ++vt) {
        vt_clear_internal(vt, background);
    }
    /*
     * Only the active VT touches the scanout buffer.  Present once after every
     * VT has been initialized so callers observe a clean console without a
     * full-screen copy for each initialization layer.
     */
    fb_console_present_locked();
    spin_unlock_irqrestore(&console_lock, flags);
}

void fb_console_tick(uint32_t ticks) {
    static int kernel_backbuffer_seeded;
    uint64_t flags;
    /*
     * Xorg/fbdev owns the real framebuffer while /dev/fb0 is open.  The text
     * console keeps its backbuffer state, but cursor blink must not dirty or
     * later replay stale underline pixels into the graphical VT.  This mirrors
     * Linux's KD_GRAPHICS expectation: no kernel text cursor is visible while
     * userspace owns the display.
     */
    if (!spin_trylock_irqsave(&console_lock, &flags)) return;
    if (!present_enabled || !cursor_enabled) {
        spin_unlock_irqrestore(&console_lock, flags);
        return;
    }
    if (!kernel_backbuffer_seeded) {
        vt_redraw(g_active_vt);
        fb_console_present_locked();
        kernel_backbuffer_seeded = 1;
        last_blink_tick = ticks;
        spin_unlock_irqrestore(&console_lock, flags);
        return;
    }
    if (ticks - last_blink_tick >= EDGE_KERNEL_TIMER_500MS_TICKS) {
        last_blink_tick = ticks;
        if (cursor_visible) {
            erase_cursor();
            cursor_visible = 0;
        } else {
            cursor_visible = 1;
            draw_cursor();
        }
        /* QEMU ramfb/Cocoa rebuilds its host surface from the guest-dirty
         * region.  Regenerate the VT before the full present so a cursor-only
         * update cannot leave the rest of the host surface black. */
        vt_redraw(g_active_vt);
        fb_console_present_locked();
    }
    spin_unlock_irqrestore(&console_lock, flags);
}

void fb_console_set_cursor_enabled(int enabled) {
    if (cursor_visible) erase_cursor();
    cursor_enabled = enabled ? 1 : 0;
    cursor_visible = cursor_enabled;
    if (cursor_visible) draw_cursor();
}

void fb_console_get_cursor(int *col, int *row) { be_get_cursor(col, row); }
int fb_console_get_cols(void) { return cols; }
int fb_console_get_rows(void) { return rows; }

static void fb_console_apply_present_state(void) {
    int enabled = present_requested && !fbdev_owned && !drm_owned;
    uint64_t flags;

    if (enabled == present_enabled) return;
    flags = spin_lock_irqsave(&console_lock);
    if (!enabled) {
        /*
         * When Xorg opens /dev/fb0, stop the text console from repainting over
         * the framebuffer.  Erase and flush the current cursor first; otherwise
         * the last underline cursor remains visible on the X root window until
         * something else happens to overwrite those pixels.
         */
        if (cursor_visible) erase_cursor();
        fb_console_present_locked();
    }
    present_enabled = enabled;
    if (present_enabled) {
        /*
         * The graphical client replaced the scanout contents while console
         * presentation was disabled.  Rebuild the active VT even when no new
         * text arrived during that interval.
         */
        cursor_visible = cursor_enabled ? 1 : 0;
        vt_redraw(g_active_vt);
        fb_console_present_locked();
    }
    spin_unlock_irqrestore(&console_lock, flags);
}

void fb_console_set_present_enabled(int enabled) {
    present_requested = enabled ? 1 : 0;
    fb_console_apply_present_state();
}

void fb_console_set_fbdev_owned(int owned) {
    fbdev_owned = owned ? 1 : 0;
    fb_console_apply_present_state();
}

void fb_console_set_drm_owned(int owned) {
    drm_owned = owned ? 1 : 0;
    fb_console_apply_present_state();
}

void fb_console_activate_vt(int vt) {
    if (vt < 1 || vt > EDGE_FB_VT_COUNT || vt == g_active_vt) return;
    g_active_vt = vt;
    cursor_visible = cursor_enabled ? 1 : 0;
    vt_redraw(vt);
    fb_console_present();
}

int fb_console_get_active_vt(void) {
    return g_active_vt;
}

void fb_console_clear_vt(int vt, uint32_t bg) {
    vt_clear_internal(vt, (uint8_t)(bg & 0x0F));
}

void fb_console_putchar_vt(int vt, char ch, uint32_t fg, uint32_t bg) {
    vt_putchar_internal(vt, ch, (uint8_t)(fg & 0x0F), (uint8_t)(bg & 0x0F));
}

void fb_console_move_cursor_vt(int vt, int x, int y) {
    vt_move_cursor_internal(vt, x, y);
}

void fb_console_get_cursor_vt(int vt, int *col, int *row) {
    fb_vt_state_t *st = vt_state(vt);
    if (!st) return;
    if (col) *col = st->cur_col;
    if (row) *row = st->cur_row;
}

void fb_console_reverse_index_vt(int vt, uint32_t bg) {
    vt_reverse_index_internal(vt, (uint8_t)(bg & 0x0f));
}

void fb_console_erase_in_line_vt(int vt, int mode, uint32_t fg, uint32_t bg) {
    (void)fg;
    vt_erase_in_line_internal(vt, mode, (uint8_t)(bg & 0x0F));
}

int fb_console_set_font(const uint8_t *data, uint32_t charcount, uint32_t width,
                        uint32_t height, uint32_t source_pitch) {
    if (!data) return -14;
    if (!(charcount == 256u || charcount == 512u)) return -22;
    if (width == 0u || width > 8u) return -22;
    if (height == 0u || height > EDGE_FB_FONT_MAX_HEIGHT) return -22;
    if (source_pitch < height || source_pitch > EDGE_FB_FONT_MAX_HEIGHT) return -22;

    memset(g_font_data, 0, sizeof(g_font_data));
    for (uint32_t ch = 0; ch < charcount; ++ch) {
        const uint8_t *src = data + ch * source_pitch;
        uint8_t *dst = g_font_data + ch * EDGE_FB_FONT_MAX_HEIGHT;
        memcpy(dst, src, height);
    }
    g_font_charcount = charcount;
    g_font_width = width;
    g_font_height = height;
    g_font_user_loaded = 1;
    fb_console_recompute_geometry();
    if (present_enabled) vt_redraw(g_active_vt);
    return 0;
}

int fb_console_get_font(uint8_t *data, uint32_t *charcount, uint32_t *width,
                        uint32_t *height, uint32_t dest_pitch) {
    if (!g_font_width || !g_font_height) fb_console_load_default_font();
    if (dest_pitch && dest_pitch < g_font_height) return -22;
    if (dest_pitch > EDGE_FB_FONT_MAX_HEIGHT) return -22;
    if (charcount) *charcount = g_font_charcount;
    if (width) *width = g_font_width;
    if (height) *height = g_font_height;
    if (data) {
        uint32_t pitch = dest_pitch ? dest_pitch : g_font_height;
        for (uint32_t ch = 0; ch < g_font_charcount; ++ch) {
            uint8_t *dst = data + ch * pitch;
            const uint8_t *src = g_font_data + ch * EDGE_FB_FONT_MAX_HEIGHT;
            memset(dst, 0, pitch);
            memcpy(dst, src, g_font_height);
        }
    }
    return 0;
}

void fb_console_reset_font(void) {
    fb_console_load_default_font();
    fb_console_recompute_geometry();
    if (present_enabled) vt_redraw(g_active_vt);
}
