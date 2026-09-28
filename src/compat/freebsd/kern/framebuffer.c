/* SPDX-License-Identifier: MPL-2.0 */
/* Shared virtual-terminal adapter for imported BSD framebuffer drivers. */

#include <stddef.h>
#include <stdint.h>

#define SC_NO_CUTPASTE 1

#include <sys/fbio.h>
#include <sys/kernel.h>

#include <dev/vt/vt.h>
#include <dev/vt/colors/vt_termcolors.h>

#include "compat/freebsd/edgeos/framebuffer.h"
#include "compat/freebsd/edgeos/systm.h"
#include "display.h"
#include "fb.h"

#define BSD_FRAMEBUFFER_EBUSY 16
#define BSD_FRAMEBUFFER_EINVAL 22

static struct vt_device g_framebuffer_device;
struct vt_device *main_vd = &g_framebuffer_device;
static const struct vt_driver *g_framebuffer_driver;
static void *g_framebuffer_softc;
static const uint8_t g_empty_glyph[32];
static eventhandler_tag g_framebuffer_register_tag;
static eventhandler_tag g_framebuffer_unregister_tag;
static struct fb_info *g_active_framebuffer;
static uint32_t g_framebuffer_registrations;
static uint32_t g_framebuffer_removals;
static uint32_t g_framebuffer_rejected;
static volatile int g_framebuffer_runtime_state;
static const struct vt_driver *g_static_framebuffer_driver;

static uint32_t
framebuffer_channel_mask(int bits, int offset)
{
    if (bits <= 0 || bits > 8 || offset < 0 || offset + bits > 32)
        return 0;
    return ((1u << bits) - 1u) << (uint32_t)offset;
}

static int
framebuffer_channel_bits(const struct fb_info *info, int channel)
{
    if (info->fb_bpp == 15)
        return 5;
    if (info->fb_bpp == 16)
        return channel == 1 ? 6 : 5;
    if (info->fb_bpp == 24 || info->fb_bpp == 32)
        return 8;
    return 0;
}

static int
framebuffer_registration_valid(const struct fb_info *info)
{
    uint64_t minimum_size;
    uint32_t bytes_per_pixel;

    if (!info || !g_framebuffer_driver || info != g_framebuffer_softc ||
        !info->fb_vbase || !info->fb_pbase || info->fb_width <= 0 ||
        info->fb_height <= 0 || info->fb_stride <= 0 ||
        (info->fb_flags & (FB_FLAG_NOMMAP | FB_FLAG_NOWRITE)) != 0 ||
        !g_framebuffer_driver->vd_fb_mmap)
        return 0;
    if (info->fb_bpp != 15 && info->fb_bpp != 16 &&
        info->fb_bpp != 24 && info->fb_bpp != 32)
        return 0;
    bytes_per_pixel = (uint32_t)(info->fb_bpp + 7) / 8u;
    if ((uint32_t)info->fb_stride <
        (uint32_t)info->fb_width * bytes_per_pixel)
        return 0;
    minimum_size = (uint64_t)(uint32_t)info->fb_stride *
        (uint64_t)(uint32_t)info->fb_height;
    return info->fb_size > 0 && (uint64_t)(uint32_t)info->fb_size >=
        minimum_size;
}

static void
framebuffer_registered(void *argument, uintptr_t value)
{
    struct fb_info *info = (struct fb_info *)(uintptr_t)value;
    uint32_t red_mask;
    uint32_t green_mask;
    uint32_t blue_mask;
    display_backend_t backend;

    (void)argument;
    if (!framebuffer_registration_valid(info)) {
        g_framebuffer_rejected++;
        return;
    }
    red_mask = framebuffer_channel_mask(
        framebuffer_channel_bits(info, 0), info->fb_rgboffs.red);
    green_mask = framebuffer_channel_mask(
        framebuffer_channel_bits(info, 1), info->fb_rgboffs.green);
    blue_mask = framebuffer_channel_mask(
        framebuffer_channel_bits(info, 2), info->fb_rgboffs.blue);
    if (!red_mask || !green_mask || !blue_mask) {
        g_framebuffer_rejected++;
        return;
    }
    fb_install_physical(info->fb_pbase,
        (uint8_t *)(uintptr_t)info->fb_vbase,
        (uint32_t)info->fb_width, (uint32_t)info->fb_height,
        (uint32_t)info->fb_stride, (uint32_t)info->fb_bpp,
        (uint32_t)info->fb_rgboffs.red,
        (uint32_t)info->fb_rgboffs.green,
        (uint32_t)info->fb_rgboffs.blue,
        red_mask, green_mask, blue_mask);
    backend = (display_backend_t) {
        .name = info->fb_name ? info->fb_name : g_framebuffer_driver->vd_name,
        .owner = info,
        .context = info,
    };
    if (display_backend_register(&backend) != 0) {
        fb_uninstall((uint8_t *)(uintptr_t)info->fb_vbase);
        g_framebuffer_rejected++;
        return;
    }
    g_active_framebuffer = info;
    g_framebuffer_registrations++;
}

static void
framebuffer_unregistered(void *argument, uintptr_t value)
{
    struct fb_info *info = (struct fb_info *)(uintptr_t)value;

    (void)argument;
    if (!info || info != g_active_framebuffer)
        return;
    if (display_backend_is_owner(info))
        fb_uninstall((uint8_t *)(uintptr_t)info->fb_vbase);
    g_active_framebuffer = 0;
    g_framebuffer_removals++;
}

int
bsd_framebuffer_runtime_initialize(void)
{
    int expected = 0;
    int state;

    if (!__atomic_compare_exchange_n(&g_framebuffer_runtime_state,
        &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        do {
            state = __atomic_load_n(&g_framebuffer_runtime_state,
                __ATOMIC_ACQUIRE);
            if (state != 1)
                return state == 2 ? 0 : BSD_FRAMEBUFFER_EINVAL;
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
        } while (1);
    }
    g_framebuffer_register_tag = EVENTHANDLER_REGISTER(
        register_framebuffer, framebuffer_registered, 0,
        EVENTHANDLER_PRI_FIRST);
    g_framebuffer_unregister_tag = EVENTHANDLER_REGISTER(
        unregister_framebuffer, framebuffer_unregistered, 0,
        EVENTHANDLER_PRI_LAST);
    if (!g_framebuffer_register_tag || !g_framebuffer_unregister_tag) {
        if (g_framebuffer_register_tag)
            EVENTHANDLER_DEREGISTER(register_framebuffer,
                g_framebuffer_register_tag);
        if (g_framebuffer_unregister_tag)
            EVENTHANDLER_DEREGISTER(unregister_framebuffer,
                g_framebuffer_unregister_tag);
        g_framebuffer_register_tag = 0;
        g_framebuffer_unregister_tag = 0;
        __atomic_store_n(&g_framebuffer_runtime_state, 3,
            __ATOMIC_RELEASE);
        return BSD_FRAMEBUFFER_EINVAL;
    }
    __atomic_store_n(&g_framebuffer_runtime_state, 2, __ATOMIC_RELEASE);
    return 0;
}

void
bsd_framebuffer_runtime_shutdown(void)
{
    struct fb_info *active = g_active_framebuffer;

    if (__atomic_load_n(&g_framebuffer_runtime_state,
        __ATOMIC_ACQUIRE) != 2)
        return;
    if (active && display_backend_is_owner(active))
        fb_uninstall((uint8_t *)(uintptr_t)active->fb_vbase);
    g_active_framebuffer = 0;
    if (g_framebuffer_register_tag)
        EVENTHANDLER_DEREGISTER(register_framebuffer,
            g_framebuffer_register_tag);
    if (g_framebuffer_unregister_tag)
        EVENTHANDLER_DEREGISTER(unregister_framebuffer,
            g_framebuffer_unregister_tag);
    g_framebuffer_register_tag = 0;
    g_framebuffer_unregister_tag = 0;
    __atomic_store_n(&g_framebuffer_runtime_state, 0, __ATOMIC_RELEASE);
}

void
bsd_framebuffer_get_status(bsd_framebuffer_status_t *status)
{
    if (!status)
        return;
    *status = (bsd_framebuffer_status_t) {
        .registrations = g_framebuffer_registrations,
        .removals = g_framebuffer_removals,
        .rejected = g_framebuffer_rejected,
        .active = g_active_framebuffer,
    };
}

static void
framebuffer_runtime_sysinit(void *argument)
{
    (void)argument;
    (void)bsd_framebuffer_runtime_initialize();
}

static void
framebuffer_runtime_sysuninit(void *argument)
{
    (void)argument;
    bsd_framebuffer_runtime_shutdown();
}

SYSINIT(edgeos_framebuffer_runtime, SI_SUB_EVENTHANDLER, SI_ORDER_MIDDLE,
    framebuffer_runtime_sysinit, 0);
SYSUNINIT(edgeos_framebuffer_runtime, SI_SUB_EVENTHANDLER, SI_ORDER_MIDDLE,
    framebuffer_runtime_sysuninit, 0);

int
vt_allocate(const struct vt_driver *driver, void *softc)
{
    struct fb_info *info;
    int result;

    if (!driver || (!softc && !driver->vd_probe))
        return BSD_FRAMEBUFFER_EINVAL;
    if (g_framebuffer_driver)
        return BSD_FRAMEBUFFER_EBUSY;
    bsd_memset(&g_framebuffer_device, 0, sizeof(g_framebuffer_device));
    g_framebuffer_device.vd_driver = driver;
    g_framebuffer_device.vd_softc = softc;
    if (driver->vd_probe &&
        driver->vd_probe(&g_framebuffer_device) == CN_DEAD) {
        bsd_memset(&g_framebuffer_device, 0,
            sizeof(g_framebuffer_device));
        return BSD_FRAMEBUFFER_EINVAL;
    }
    if (driver->vd_init) {
        result = driver->vd_init(&g_framebuffer_device);
        if (result == CN_DEAD) {
            bsd_memset(&g_framebuffer_device, 0,
                sizeof(g_framebuffer_device));
            return BSD_FRAMEBUFFER_EINVAL;
        }
    }
    info = g_framebuffer_device.vd_softc;
    if (!info) {
        bsd_memset(&g_framebuffer_device, 0,
            sizeof(g_framebuffer_device));
        return BSD_FRAMEBUFFER_EINVAL;
    }
    g_framebuffer_driver = driver;
    g_framebuffer_softc = info;
    result = register_framebuffer(info);
    if (result != 0) {
        if (driver->vd_fini)
            driver->vd_fini(&g_framebuffer_device, info);
        bsd_memset(&g_framebuffer_device, 0,
            sizeof(g_framebuffer_device));
        g_framebuffer_driver = 0;
        g_framebuffer_softc = 0;
    }
    return result;
}

int
vt_deallocate(const struct vt_driver *driver, void *softc)
{
    struct fb_info *info = softc;

    if (!driver || !softc || g_framebuffer_driver != driver ||
        g_framebuffer_softc != softc)
        return BSD_FRAMEBUFFER_EINVAL;
    (void)unregister_framebuffer(info);
    if (driver->vd_fini)
        driver->vd_fini(&g_framebuffer_device, softc);
    bsd_memset(&g_framebuffer_device, 0, sizeof(g_framebuffer_device));
    g_framebuffer_driver = 0;
    g_framebuffer_softc = 0;
    return 0;
}

void
vt_driver_register(const struct vt_driver *driver)
{
    if (!driver || !driver->vd_probe)
        return;
    if (!g_static_framebuffer_driver || driver->vd_priority >
        g_static_framebuffer_driver->vd_priority)
        g_static_framebuffer_driver = driver;
}

int
vt_probe_static_drivers(void)
{
    if (g_framebuffer_driver)
        return 0;
    if (!g_static_framebuffer_driver)
        return BSD_FRAMEBUFFER_EINVAL;
    return vt_allocate(g_static_framebuffer_driver, 0);
}

#ifndef BSD_BRIDGE_HOST_TEST
static void
framebuffer_probe_static_driver(void *argument)
{
    (void)argument;
    (void)vt_probe_static_drivers();
}

SYSINIT(edgeos_framebuffer_static_probe, SI_SUB_DRIVERS, SI_ORDER_FIRST,
    framebuffer_probe_static_driver, 0);
#endif

void
vt_suspend(struct vt_device *device)
{
    (void)device;
}

void
vt_resume(struct vt_device *device)
{
    (void)device;
}

int
vtbuf_iscursor(const struct vt_buf *buffer, int row, int column)
{
    (void)buffer;
    (void)row;
    (void)column;
    return 0;
}

const uint8_t *
vtfont_lookup(const struct vt_font *font, term_char_t character)
{
    (void)font;
    (void)character;
    return g_empty_glyph;
}

void
vt_determine_colors(term_char_t character, int cursor,
    term_color_t *foreground, term_color_t *background)
{
    term_color_t temporary;
    int invert = 0;

    *foreground = TCHAR_FGCOLOR(character);
    if ((TCHAR_FORMAT(character) & TF_BOLD) != 0)
        *foreground = TCOLOR_LIGHT(*foreground);
    *background = TCHAR_BGCOLOR(character);
    if ((TCHAR_FORMAT(character) & TF_BLINK) != 0)
        *background = TCOLOR_LIGHT(*background);
    if ((TCHAR_FORMAT(character) & TF_REVERSE) != 0)
        invert ^= 1;
    if (cursor)
        invert ^= 1;
    if (invert) {
        temporary = *foreground;
        *foreground = *background;
        *background = temporary;
    }
}

int
vt_config_cons_colors(struct fb_info *info, int format, uint32_t red_max,
    int red_offset, uint32_t green_max, int green_offset,
    uint32_t blue_max, int blue_offset)
{
    static const uint8_t palette[16][3] = {
        {0, 0, 0}, {0, 0, 170}, {0, 170, 0}, {0, 170, 170},
        {170, 0, 0}, {170, 0, 170}, {170, 85, 0}, {170, 170, 170},
        {85, 85, 85}, {85, 85, 255}, {85, 255, 85}, {85, 255, 255},
        {255, 85, 85}, {255, 85, 255}, {255, 255, 85}, {255, 255, 255},
    };

    if (!info || format != COLOR_FORMAT_RGB)
        return 19;
    info->fb_rgboffs.red = red_offset;
    info->fb_rgboffs.green = green_offset;
    info->fb_rgboffs.blue = blue_offset;
    for (unsigned int index = 0; index < 16; ++index) {
        uint32_t red = red_max * palette[index][0] / 255U;
        uint32_t green = green_max * palette[index][1] / 255U;
        uint32_t blue = blue_max * palette[index][2] / 255U;

        info->fb_cmap[index] = (red << red_offset) |
            (green << green_offset) | (blue << blue_offset);
    }
    return 0;
}
