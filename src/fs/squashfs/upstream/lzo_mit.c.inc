/* SPDX-License-Identifier: MIT */
/*
 * Adapted from lzokay by Jack Andersen (https://github.com/AxioDL/lzokay).
 * Copyright (c) 2018 Jack Andersen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

static bool sqfs_lzo_length(const uint8_t *src, size_t src_size, size_t *input,
                            size_t base, size_t limit, size_t *length) {
    if (base > limit) return false;
    while (*input < src_size && src[*input] == 0) {
        if (limit - base < 255) return false;
        base += 255;
        ++*input;
    }
    if (*input == src_size || src[*input] > limit - base) return false;
    *length = base + src[(*input)++];
    return true;
}

static sqfs_err sqfs_decompressor_lzo(void *in, size_t insz,
                                      void *out, size_t *outsz) {
    const uint8_t *src = in;
    uint8_t *dst = out;
    size_t input = 0, output = 0, state = 0, length, distance, next_state;
    size_t capacity;
    uint8_t instruction;
    uint16_t word;

    if (!src || !dst || !outsz || insz < 3) return SQFS_ERR;
    capacity = *outsz;

    if (src[0] >= 22) {
        length = src[input++] - 17;
        if (length > insz - input || length > capacity) return SQFS_ERR;
        memcpy(dst, src + input, length);
        input += length;
        output = length;
        state = 4;
    } else if (src[0] >= 18) {
        length = src[input++] - 17;
        if (length > insz - input || length > capacity) return SQFS_ERR;
        memcpy(dst, src + input, length);
        input += length;
        output = length;
        state = length;
    }

    for (;;) {
        if (input == insz) return SQFS_ERR;
        instruction = src[input++];
        next_state = 0;

        if (instruction & 0xc0) {
            if (input == insz) return SQFS_ERR;
            distance = ((size_t)src[input++] << 3) +
                       ((instruction >> 2) & 7) + 1;
            length = (instruction >> 5) + 1;
            next_state = instruction & 3;
        } else if (instruction & 0x20) {
            length = (instruction & 31) + 2;
            if (length == 2 &&
                !sqfs_lzo_length(src, insz, &input, 33,
                                 capacity - output, &length)) return SQFS_ERR;
            if (insz - input < 2) return SQFS_ERR;
            word = (uint16_t)src[input] | ((uint16_t)src[input + 1] << 8);
            input += 2;
            distance = (word >> 2) + 1;
            next_state = word & 3;
        } else if (instruction & 0x10) {
            length = (instruction & 7) + 2;
            if (length == 2 &&
                !sqfs_lzo_length(src, insz, &input, 9,
                                 capacity - output, &length)) return SQFS_ERR;
            if (insz - input < 2) return SQFS_ERR;
            word = (uint16_t)src[input] | ((uint16_t)src[input + 1] << 8);
            input += 2;
            distance = ((size_t)(instruction & 8) << 11) + (word >> 2);
            next_state = word & 3;
            if (distance == 0) {
                if (length != 3 || input != insz) return SQFS_ERR;
                *outsz = output;
                return SQFS_OK;
            }
            distance += 16384;
        } else if (state == 0) {
            length = instruction + 3;
            if (length == 3 &&
                !sqfs_lzo_length(src, insz, &input, 18,
                                 capacity - output, &length)) return SQFS_ERR;
            if (length > insz - input || length > capacity - output)
                return SQFS_ERR;
            memcpy(dst + output, src + input, length);
            input += length;
            output += length;
            state = 4;
            continue;
        } else {
            if (input == insz) return SQFS_ERR;
            next_state = instruction & 3;
            distance = (instruction >> 2) + ((size_t)src[input++] << 2) +
                       (state == 4 ? 2049 : 1);
            length = state == 4 ? 3 : 2;
        }

        if (distance == 0 || distance > output ||
            length > capacity - output ||
            next_state > capacity - output - length ||
            next_state > insz - input) return SQFS_ERR;
        for (size_t index = 0; index < length; ++index)
            dst[output + index] = dst[output + index - distance];
        output += length;
        memcpy(dst + output, src + input, next_state);
        output += next_state;
        input += next_state;
        state = next_state;
    }
}
