/* SPDX-License-Identifier: MPL-2.0 */
/* EDID and DisplayID timing parser for architecture-independent display backends. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "display.h"

#define EDID_BLOCK_BYTES 128u
#define EDID_BASE_DTD_OFFSET 54u
#define EDID_BASE_DTD_COUNT 4u
#define EDID_DTD_BYTES 18u
#define EDID_CTA_EXTENSION 0x02u
#define EDID_DISPLAYID_EXTENSION 0x70u
#define DISPLAYID_TYPE_I_TIMING 0x03u
#define CTA_EXTENDED_DATA_BLOCK 0x07u
#define CTA_DISPLAYID_TYPE_VII_TIMING 34u

typedef struct display_edid_accumulator {
    display_mode_t *modes;
    uint32_t capacity;
    uint32_t count;
} display_edid_accumulator_t;

static uint16_t
display_edid_u16(const uint8_t *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static int
display_edid_checksum_valid(const uint8_t *block)
{
    uint8_t sum = 0;

    for (uint32_t index = 0; index < EDID_BLOCK_BYTES; ++index)
        sum = (uint8_t)(sum + block[index]);
    return sum == 0;
}

static int
display_edid_append(display_edid_accumulator_t *output,
                    const display_mode_t *mode)
{
    display_mode_t normalized;

    if (!output || !mode)
        return 0;
    normalized = *mode;
    if (!normalized.refresh_millihz && normalized.pixel_clock_khz &&
        normalized.htotal && normalized.vtotal) {
        normalized.refresh_millihz = (uint32_t)(
            ((uint64_t)normalized.pixel_clock_khz * 1000000ull +
             ((uint64_t)normalized.htotal * normalized.vtotal) / 2u) /
            ((uint64_t)normalized.htotal * normalized.vtotal));
    }
    if (!display_mode_valid(&normalized))
        return 0;
    for (uint32_t index = 0; index < output->count; ++index) {
        if (!display_mode_equal(&output->modes[index], &normalized))
            continue;
        if ((normalized.flags & DISPLAY_MODE_PREFERRED) != 0)
            output->modes[index].flags |= DISPLAY_MODE_PREFERRED;
        return 1;
    }
    if (output->count >= output->capacity)
        return 0;
    output->modes[output->count++] = normalized;
    return 1;
}

static int
display_edid_parse_dtd(const uint8_t *data, int preferred,
                       display_mode_t *mode)
{
    uint32_t hactive;
    uint32_t hblank;
    uint32_t vactive;
    uint32_t vblank;
    uint32_t hsync_offset;
    uint32_t hsync_width;
    uint32_t vsync_offset;
    uint32_t vsync_width;

    if (!data || !mode || (data[0] == 0u && data[1] == 0u))
        return 0;
    memset(mode, 0, sizeof(*mode));
    mode->pixel_clock_khz = (uint32_t)display_edid_u16(data) * 10u;
    hactive = data[2] | ((uint32_t)(data[4] & 0xf0u) << 4);
    hblank = data[3] | ((uint32_t)(data[4] & 0x0fu) << 8);
    vactive = data[5] | ((uint32_t)(data[7] & 0xf0u) << 4);
    vblank = data[6] | ((uint32_t)(data[7] & 0x0fu) << 8);
    hsync_offset = data[8] | ((uint32_t)(data[11] & 0xc0u) << 2);
    hsync_width = data[9] | ((uint32_t)(data[11] & 0x30u) << 4);
    vsync_offset = (data[10] >> 4) |
        ((uint32_t)(data[11] & 0x0cu) << 2);
    vsync_width = (data[10] & 0x0fu) |
        ((uint32_t)(data[11] & 0x03u) << 4);
    if (!hactive || !vactive || !hblank || !vblank ||
        !hsync_width || !vsync_width)
        return 0;
    mode->width = hactive;
    mode->height = vactive;
    mode->hsync_start = (uint16_t)(hactive + hsync_offset);
    mode->hsync_end = (uint16_t)(mode->hsync_start + hsync_width);
    mode->htotal = (uint16_t)(hactive + hblank);
    mode->vsync_start = (uint16_t)(vactive + vsync_offset);
    mode->vsync_end = (uint16_t)(mode->vsync_start + vsync_width);
    mode->vtotal = (uint16_t)(vactive + vblank);
    if (preferred)
        mode->flags |= DISPLAY_MODE_PREFERRED;
    if (data[17] & 0x80u)
        mode->flags |= DISPLAY_MODE_INTERLACE;
    if ((data[17] & 0x18u) == 0x18u) {
        mode->flags |= data[17] & 0x02u ?
            DISPLAY_MODE_PHSYNC : DISPLAY_MODE_NHSYNC;
        mode->flags |= data[17] & 0x04u ?
            DISPLAY_MODE_PVSYNC : DISPLAY_MODE_NVSYNC;
    }
    return 1;
}

static void
display_edid_parse_standard(const uint8_t *data,
                            display_edid_accumulator_t *output)
{
    display_mode_t mode;
    uint32_t aspect;

    if (!data || (data[0] == 0x01u && data[1] == 0x01u))
        return;
    memset(&mode, 0, sizeof(mode));
    mode.width = ((uint32_t)data[0] + 31u) * 8u;
    aspect = data[1] >> 6;
    if (aspect == 0u)
        mode.height = mode.width * 10u / 16u;
    else if (aspect == 1u)
        mode.height = mode.width * 3u / 4u;
    else if (aspect == 2u)
        mode.height = mode.width * 4u / 5u;
    else
        mode.height = mode.width * 9u / 16u;
    mode.refresh_millihz = ((data[1] & 0x3fu) + 60u) * 1000u;
    display_edid_append(output, &mode);
}

static void
display_edid_parse_displayid_timing(const uint8_t *data, int type_vii,
                                    display_edid_accumulator_t *output)
{
    display_mode_t mode;
    uint32_t clock_unit_khz = type_vii ? 1u : 10u;
    uint32_t raw_clock;
    uint32_t hblank;
    uint32_t vblank;
    uint32_t hsync_offset;
    uint32_t hsync_width;
    uint32_t vsync_offset;
    uint32_t vsync_width;

    if (!data)
        return;
    memset(&mode, 0, sizeof(mode));
    raw_clock = data[0] | ((uint32_t)data[1] << 8) |
        ((uint32_t)data[2] << 16);
    mode.pixel_clock_khz = (raw_clock + 1u) * clock_unit_khz;
    mode.width = 1u + display_edid_u16(data + 4u);
    hblank = 1u + display_edid_u16(data + 6u);
    hsync_offset = 1u + data[8] +
        ((uint32_t)(data[9] & 0x7fu) << 8);
    hsync_width = 1u + display_edid_u16(data + 10u);
    mode.height = 1u + display_edid_u16(data + 12u);
    vblank = 1u + display_edid_u16(data + 14u);
    vsync_offset = 1u + data[16] +
        ((uint32_t)(data[17] & 0x7fu) << 8);
    vsync_width = 1u + display_edid_u16(data + 18u);
    if (mode.width > UINT16_MAX - hblank ||
        mode.height > UINT16_MAX - vblank ||
        hsync_offset > hblank || hsync_width > hblank - hsync_offset ||
        vsync_offset > vblank || vsync_width > vblank - vsync_offset)
        return;
    mode.hsync_start = (uint16_t)(mode.width + hsync_offset);
    mode.hsync_end = (uint16_t)(mode.hsync_start + hsync_width);
    mode.htotal = (uint16_t)(mode.width + hblank);
    mode.vsync_start = (uint16_t)(mode.height + vsync_offset);
    mode.vsync_end = (uint16_t)(mode.vsync_start + vsync_width);
    mode.vtotal = (uint16_t)(mode.height + vblank);
    if (data[3] & 0x80u)
        mode.flags |= DISPLAY_MODE_PREFERRED;
    if (data[3] & 0x10u)
        mode.flags |= DISPLAY_MODE_INTERLACE;
    mode.flags |= data[9] & 0x80u ?
        DISPLAY_MODE_PHSYNC : DISPLAY_MODE_NHSYNC;
    mode.flags |= data[17] & 0x80u ?
        DISPLAY_MODE_PVSYNC : DISPLAY_MODE_NVSYNC;
    display_edid_append(output, &mode);
}

static void
display_edid_parse_cta(const uint8_t *block,
                       display_edid_accumulator_t *output)
{
    uint32_t dtd_offset = block[2];
    uint32_t position = 4u;

    if (dtd_offset < 4u || dtd_offset > 127u)
        dtd_offset = 127u;
    while (position < dtd_offset) {
        uint32_t tag = block[position] >> 5;
        uint32_t length = block[position] & 0x1fu;
        const uint8_t *payload = block + position + 1u;

        if (position + 1u + length > dtd_offset)
            break;
        if (tag == CTA_EXTENDED_DATA_BLOCK && length == 22u &&
            payload[0] == CTA_DISPLAYID_TYPE_VII_TIMING &&
            (payload[1] & 0x07u) == 2u)
            display_edid_parse_displayid_timing(payload + 2u, 1, output);
        position += length + 1u;
    }
    for (position = dtd_offset;
         position + EDID_DTD_BYTES <= 127u;
         position += EDID_DTD_BYTES) {
        display_mode_t mode;

        if (display_edid_parse_dtd(block + position, 0, &mode))
            display_edid_append(output, &mode);
    }
}

static void
display_edid_parse_displayid(const uint8_t *block,
                             display_edid_accumulator_t *output)
{
    uint32_t payload_length = block[2];
    uint32_t end = 5u + payload_length;
    uint32_t position = 5u;

    if (end > 127u)
        end = 127u;
    while (position + 3u <= end) {
        uint32_t tag = block[position];
        uint32_t length = block[position + 2u];
        const uint8_t *payload = block + position + 3u;

        if (position + 3u + length > end)
            break;
        if (tag == DISPLAYID_TYPE_I_TIMING) {
            for (uint32_t offset = 0; offset + 20u <= length; offset += 20u)
                display_edid_parse_displayid_timing(
                    payload + offset, 0, output);
        }
        position += 3u + length;
    }
}

int
display_edid_parse(const uint8_t *edid, uint32_t length,
                   display_mode_t *modes, uint32_t capacity,
                   uint32_t *width_mm, uint32_t *height_mm)
{
    static const uint8_t signature[8] = {
        0x00u, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0x00u,
    };
    display_edid_accumulator_t output = {
        .modes = modes,
        .capacity = capacity,
    };
    uint32_t block_count;

    if (!edid || !modes || !capacity || length < EDID_BLOCK_BYTES ||
        memcmp(edid, signature, sizeof(signature)) != 0 ||
        !display_edid_checksum_valid(edid))
        return -1;
    if (width_mm)
        *width_mm = (uint32_t)edid[21] * 10u;
    if (height_mm)
        *height_mm = (uint32_t)edid[22] * 10u;

    for (uint32_t index = 0; index < EDID_BASE_DTD_COUNT; ++index) {
        display_mode_t mode;
        const uint8_t *descriptor = edid + EDID_BASE_DTD_OFFSET +
            index * EDID_DTD_BYTES;

        if (display_edid_parse_dtd(descriptor, index == 0u, &mode))
            display_edid_append(&output, &mode);
    }
    for (uint32_t index = 0; index < 8u; ++index)
        display_edid_parse_standard(edid + 38u + index * 2u, &output);

    block_count = 1u + edid[126];
    if (block_count > length / EDID_BLOCK_BYTES)
        block_count = length / EDID_BLOCK_BYTES;
    for (uint32_t block_index = 1u; block_index < block_count;
         ++block_index) {
        const uint8_t *block = edid + block_index * EDID_BLOCK_BYTES;

        if (!display_edid_checksum_valid(block))
            continue;
        if (block[0] == EDID_CTA_EXTENSION)
            display_edid_parse_cta(block, &output);
        else if (block[0] == EDID_DISPLAYID_EXTENSION)
            display_edid_parse_displayid(block, &output);
    }
    return output.count ? (int)output.count : -1;
}
