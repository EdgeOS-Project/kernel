/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for shared BSD framebuffer registration. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#define SC_NO_CUTPASTE 1

#include <sys/eventhandler.h>
#include <sys/fbio.h>
#include <dev/vt/vt.h>
#include <dev/vt/colors/vt_termcolors.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/framebuffer.h"
#include "compat/freebsd/edgeos/module.h"
#include "display.h"
#include "fb.h"

static int g_init_count;
static int g_fini_count;
static int g_register_count;
static int g_unregister_count;
static int g_install_count;
static int g_uninstall_count;
static uint8_t *g_installed_address;

void
bsd_static_record_register(enum bsd_static_record_kind kind,
    const void *record)
{
    assert(kind == BSD_STATIC_SYSINIT || kind == BSD_STATIC_SYSUNINIT);
    assert(record != 0);
}

void
fb_install_physical(uint64_t physical_address, uint8_t *kernel_address,
    uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp,
    uint32_t red_position, uint32_t green_position, uint32_t blue_position,
    uint32_t red_mask, uint32_t green_mask, uint32_t blue_mask)
{
    assert(physical_address == 0x200000);
    assert(kernel_address != 0);
    assert(width == 800 && height == 600);
    assert(pitch == 800 * 4 && bpp == 32);
    assert(red_position == 16 && green_position == 8 && blue_position == 0);
    assert(red_mask == 0x00ff0000);
    assert(green_mask == 0x0000ff00);
    assert(blue_mask == 0x000000ff);
    g_installed_address = kernel_address;
    g_install_count++;
}

void
fb_uninstall(uint8_t *expected_kernel_address)
{
    assert(expected_kernel_address == g_installed_address);
    display_backend_reset();
    g_uninstall_count++;
}

static int
test_init(struct vt_device *device)
{
    assert(device != 0);
    g_init_count++;
    return CN_INTERNAL;
}

static void
test_fini(struct vt_device *device, void *softc)
{
    assert(device != 0);
    assert(softc != 0);
    g_fini_count++;
}

static void
test_register(void *argument, uintptr_t framebuffer)
{
    int *count = argument;

    assert(framebuffer != 0);
    (*count)++;
}

static int
test_mmap(struct vt_device *device, uint64_t offset,
    uint64_t *physical_address, int protection, char *attribute)
{
    (void)device;
    (void)offset;
    (void)physical_address;
    (void)protection;
    (void)attribute;
    return 0;
}

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U,
        (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

int
main(void)
{
    bsd_allocator_ops_t operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    struct vt_driver driver = {
        .vd_name = "test",
        .vd_init = test_init,
        .vd_fini = test_fini,
        .vd_fb_mmap = test_mmap,
        .vd_priority = VD_PRIORITY_GENERIC,
    };
    struct fb_info info = {
        .fb_width = 800,
        .fb_height = 600,
        .fb_size = 800 * 600 * 4,
        .fb_stride = 800 * 4,
        .fb_bpp = 32,
        .fb_pbase = 0x200000,
        .fb_vbase = (uintptr_t)0x400000,
        .fb_name = "bsd-test-fb",
    };
    eventhandler_tag registered;
    eventhandler_tag unregistered;

    assert(bsd_allocator_initialize(&operations) == 0);
    assert(bsd_framebuffer_runtime_initialize() == 0);
    assert(bsd_framebuffer_runtime_initialize() == 0);
    registered = EVENTHANDLER_REGISTER(register_framebuffer,
        test_register, &g_register_count, EVENTHANDLER_PRI_ANY);
    unregistered = EVENTHANDLER_REGISTER(unregister_framebuffer,
        test_register, &g_unregister_count, EVENTHANDLER_PRI_ANY);
    assert(registered != 0);
    assert(unregistered != 0);
    assert(vt_config_cons_colors(&info, COLOR_FORMAT_RGB,
        255, 16, 255, 8, 255, 0) == 0);
    assert(info.fb_cmap[15] == 0x00ffffffU);
    assert(vt_allocate(&driver, &info) == 0);
    assert(g_init_count == 1);
    assert(g_register_count == 1);
    assert(g_install_count == 1);
    assert(display_backend_is_owner(&info));
    assert(!display_backend_requires_present());
    assert(vt_deallocate(&driver, &info) == 0);
    assert(g_fini_count == 1);
    assert(g_unregister_count == 1);
    assert(g_uninstall_count == 1);
    assert(!display_backend_is_owner(&info));
    {
        bsd_framebuffer_status_t status;

        bsd_framebuffer_get_status(&status);
        assert(status.registrations == 1);
        assert(status.removals == 1);
        assert(status.rejected == 0);
        assert(status.active == 0);
    }
    EVENTHANDLER_DEREGISTER(register_framebuffer, registered);
    EVENTHANDLER_DEREGISTER(unregister_framebuffer, unregistered);
    bsd_framebuffer_runtime_shutdown();
    return 0;
}
