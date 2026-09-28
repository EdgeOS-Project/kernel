/* SPDX-License-Identifier: MPL-2.0 */
/* Linux compat fbdev ioctl layout unit test. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dev/fbdev.h"
#include "fb.h"
#include "kernel/fbdev_runtime.h"
#include "kernel/ioctl_runtime.h"

fb_t fb;

static int failures;
static struct edge_fb_fix_screeninfo32 fixed32;
static uint32_t fixed_canary = UINT32_C(0x51f1cafe);
static struct edge_fb_cmap32 colormap32;
static uint16_t red[2];
static uint16_t green[2];
static uint16_t blue[2];

#define USER_FIXED UINT32_C(0x1000)
#define USER_COLORMAP UINT32_C(0x2000)
#define USER_RED UINT32_C(0x3000)
#define USER_GREEN UINT32_C(0x4000)
#define USER_BLUE UINT32_C(0x5000)

static void expect(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
}

int fb_get_2m_phys_window(uint64_t *physical_base, uint32_t *page_count,
                          uint64_t *offset) {
    *physical_base = UINT64_C(0x12000000);
    *page_count = 4;
    *offset = UINT64_C(0x345000);
    return 1;
}

static void *user_buffer(uint64_t address, uint64_t size) {
    if (address >= USER_FIXED &&
        address + size <= USER_FIXED + sizeof(fixed32))
        return (uint8_t *)&fixed32 + (address - USER_FIXED);
    if (address >= USER_COLORMAP &&
        address + size <= USER_COLORMAP + sizeof(colormap32))
        return (uint8_t *)&colormap32 + (address - USER_COLORMAP);
    if (address >= USER_RED &&
        address + size <= USER_RED + sizeof(red))
        return (uint8_t *)red + (address - USER_RED);
    if (address >= USER_GREEN &&
        address + size <= USER_GREEN + sizeof(green))
        return (uint8_t *)green + (address - USER_GREEN);
    if (address >= USER_BLUE &&
        address + size <= USER_BLUE + sizeof(blue))
        return (uint8_t *)blue + (address - USER_BLUE);
    return 0;
}

static int copy_from_user(void *context, void *destination,
                          uint64_t source, uint64_t size) {
    void *buffer = user_buffer(source, size);
    (void)context;
    if (!buffer) return -1;
    memcpy(destination, buffer, (size_t)size);
    return 0;
}

static int copy_to_user(void *context, uint64_t destination,
                        const void *source, uint64_t size) {
    void *buffer = user_buffer(destination, size);
    (void)context;
    if (!buffer) return -1;
    memcpy(buffer, source, (size_t)size);
    return 0;
}

static kernel_ioctl_request_t request_for(uint32_t command,
                                          uint64_t argument) {
    kernel_ioctl_request_t request;
    memset(&request, 0, sizeof(request));
    request.command = command;
    request.argument = argument;
    request.copy_from_user = copy_from_user;
    request.copy_to_user = copy_to_user;
    request.user_pointer_size = sizeof(uint32_t);
    return request;
}

static void test_fixed_information(void) {
    kernel_ioctl_request_t request = request_for(
        LINUX_FBIOGET_FSCREENINFO, USER_FIXED);

    memset(&fixed32, 0xa5, sizeof(fixed32));
    fixed_canary = UINT32_C(0x51f1cafe);
    expect("fixed result", kernel_fbdev_ioctl(&request) == 0);
    expect("fixed identity", memcmp(fixed32.id, "EdgeOS framebuffer", 16) == 0);
    expect("fixed address", fixed32.smem_start == UINT32_C(0x12345000));
    expect("fixed length", fixed32.smem_len == fb.pitch * fb.height);
    expect("fixed line length", fixed32.line_length == fb.pitch);
    expect("fixed canary", fixed_canary == UINT32_C(0x51f1cafe));
}

static void test_colormap(void) {
    kernel_ioctl_request_t request;

    memset(&colormap32, 0, sizeof(colormap32));
    colormap32.start = 1;
    colormap32.len = 2;
    colormap32.red = USER_RED;
    colormap32.green = USER_GREEN;
    colormap32.blue = USER_BLUE;
    request = request_for(LINUX_FBIOGETCMAP, USER_COLORMAP);
    expect("colormap result", kernel_fbdev_ioctl(&request) == 0);
    expect("colormap red", red[0] == 257u && red[1] == 514u);
    expect("colormap green", green[0] == 257u && green[1] == 514u);
    expect("colormap blue", blue[0] == 257u && blue[1] == 514u);
}

int main(void) {
    memset(&fb, 0, sizeof(fb));
    fb.width = 1920;
    fb.height = 1080;
    fb.pitch = 7680;
    fb.bpp = 32;
    fb.r_mask = fb.g_mask = fb.b_mask = 0xff;
    fb.r_pos = 16;
    fb.g_pos = 8;
    fb.b_pos = 0;
    test_fixed_information();
    test_colormap();
    if (failures) return 1;
    puts("fbdev compat ioctl unit: PASS");
    return 0;
}
