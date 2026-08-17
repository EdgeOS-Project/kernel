/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent Linux fbdev ioctl policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "dev/fbdev.h"
#include "fb.h"
#include "kernel/fbdev_runtime.h"
#include "kernel/linux_errno.h"
#include "string.h"

static uint32_t framebuffer_mask_width(uint32_t mask) {
    uint32_t width = 0;
    while (mask) {
        width += mask & 1u;
        mask >>= 1;
    }
    return width;
}

static int fbdev_copy_from_user(const kernel_ioctl_request_t *request,
                                void *destination, uint64_t source,
                                uint64_t size) {
    if (!request || !request->copy_from_user) return -1;
    return request->copy_from_user(request->copy_context, destination,
                                   source, size);
}

static int fbdev_copy_to_user(const kernel_ioctl_request_t *request,
                              uint64_t destination, const void *source,
                              uint64_t size) {
    if (!request || !request->copy_to_user) return -1;
    return request->copy_to_user(request->copy_context, destination,
                                 source, size);
}

static int64_t fbdev_colormap_ioctl(
    const kernel_ioctl_request_t *request) {
    struct edge_fb_cmap colormap;

    if (!request->argument) return -EDGE_LINUX_EFAULT;
    if (fbdev_copy_from_user(request, &colormap, request->argument,
                             sizeof(colormap)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (colormap.len > 65536u) return -EDGE_LINUX_EINVAL;
    if (colormap.len &&
        (!colormap.red || !colormap.green || !colormap.blue))
        return -EDGE_LINUX_EFAULT;

    for (uint32_t index = 0; index < colormap.len; ++index) {
        uint64_t offset = (uint64_t)index * sizeof(uint16_t);
        uint32_t color_index = colormap.start + index;
        uint16_t value = color_index > 255u ?
            0xffffu : (uint16_t)(color_index * 257u);
        uint16_t alpha = 0xffffu;

        if (request->command == LINUX_FBIOGETCMAP) {
            if (fbdev_copy_to_user(request, colormap.red + offset,
                                   &value, sizeof(value)) < 0 ||
                fbdev_copy_to_user(request, colormap.green + offset,
                                   &value, sizeof(value)) < 0 ||
                fbdev_copy_to_user(request, colormap.blue + offset,
                                   &value, sizeof(value)) < 0 ||
                (colormap.transp &&
                 fbdev_copy_to_user(request, colormap.transp + offset,
                                    &alpha, sizeof(alpha)) < 0))
                return -EDGE_LINUX_EFAULT;
        } else if (request->command == LINUX_FBIOPUTCMAP) {
            if (fbdev_copy_from_user(request, &value,
                                     colormap.red + offset,
                                     sizeof(value)) < 0 ||
                fbdev_copy_from_user(request, &value,
                                     colormap.green + offset,
                                     sizeof(value)) < 0 ||
                fbdev_copy_from_user(request, &value,
                                     colormap.blue + offset,
                                     sizeof(value)) < 0 ||
                (colormap.transp &&
                 fbdev_copy_from_user(request, &value,
                                      colormap.transp + offset,
                                      sizeof(value)) < 0))
                return -EDGE_LINUX_EFAULT;
        } else {
            return -EDGE_LINUX_ENOTTY;
        }
    }
    return 0;
}

int64_t kernel_fbdev_ioctl(const kernel_ioctl_request_t *request) {
    uint64_t physical_base = 0;
    uint64_t physical_offset = 0;
    uint32_t physical_pages = 0;

    if (!request) return -EDGE_LINUX_EINVAL;
    if (!fb_get_2m_phys_window(&physical_base, &physical_pages,
                               &physical_offset))
        return -EDGE_LINUX_ENODEV;
    (void)physical_pages;

    if (request->command == LINUX_FBIOGET_FSCREENINFO) {
        struct edge_fb_fix_screeninfo fixed;
        static const char identity[] = "EdgeOS framebuffer";

        if (!request->argument) return -EDGE_LINUX_EFAULT;
        memset(&fixed, 0, sizeof(fixed));
        memcpy(fixed.id, identity, sizeof(fixed.id));
        fixed.smem_start = physical_base + physical_offset;
        fixed.smem_len = fb.pitch * fb.height;
        fixed.type = 0u;
        fixed.visual = 2u;
        fixed.line_length = fb.pitch;
        return fbdev_copy_to_user(request, request->argument,
                                  &fixed, sizeof(fixed)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    if (request->command == LINUX_FBIOGET_VSCREENINFO) {
        struct edge_fb_var_screeninfo variable;

        if (!request->argument) return -EDGE_LINUX_EFAULT;
        memset(&variable, 0, sizeof(variable));
        variable.xres = variable.xres_virtual = fb.width;
        variable.yres = variable.yres_virtual = fb.height;
        variable.bits_per_pixel = fb.bpp;
        variable.red.offset = fb.r_pos;
        variable.red.length = framebuffer_mask_width(fb.r_mask);
        variable.green.offset = fb.g_pos;
        variable.green.length = framebuffer_mask_width(fb.g_mask);
        variable.blue.offset = fb.b_pos;
        variable.blue.length = framebuffer_mask_width(fb.b_mask);
        variable.transp.offset = 24u;
        variable.transp.length = fb.bpp == 32u ? 8u : 0u;
        variable.width = (fb.width * 254u + 480u) / 960u;
        variable.height = (fb.height * 254u + 480u) / 960u;
        if (!variable.width) variable.width = 1u;
        if (!variable.height) variable.height = 1u;
        return fbdev_copy_to_user(request, request->argument,
                                  &variable, sizeof(variable)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    if (request->command == LINUX_FBIOGETCMAP ||
        request->command == LINUX_FBIOPUTCMAP)
        return fbdev_colormap_ioctl(request);
    if (request->command == LINUX_FBIOPUT_VSCREENINFO ||
        request->command == LINUX_FBIOPAN_DISPLAY) {
        struct edge_fb_var_screeninfo variable;

        if (!request->argument ||
            fbdev_copy_from_user(request, &variable, request->argument,
                                 sizeof(variable)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (variable.xres != fb.width || variable.yres != fb.height ||
            variable.bits_per_pixel != fb.bpp ||
            variable.xres_virtual < variable.xres ||
            variable.yres_virtual < variable.yres ||
            variable.xoffset > variable.xres_virtual - variable.xres ||
            variable.yoffset > variable.yres_virtual - variable.yres)
            return -EDGE_LINUX_EINVAL;
        return 0;
    }
    if (request->command == LINUX_FBIOBLANK)
        return request->argument <= 4u ? 0 : -EDGE_LINUX_EINVAL;
    if (request->command == LINUX_FBIO_WAITFORVSYNC)
        return 0;
    return -EDGE_LINUX_ENOTTY;
}
