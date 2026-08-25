/* SPDX-License-Identifier: MPL-2.0 */
/* SHA-1 as specified by FIPS 180-4. */

#include "kernel/sha1_runtime.h"
#include "string.h"

static uint32_t sha1_rotate_left(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32u - count));
}

static uint32_t sha1_load_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24u) |
           ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) |
           (uint32_t)bytes[3];
}

static void sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t words[80];
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    for (uint32_t index = 0; index < 16u; ++index)
        words[index] = sha1_load_be32(block + index * 4u);
    for (uint32_t index = 16u; index < 80u; ++index)
        words[index] = sha1_rotate_left(
            words[index - 3u] ^ words[index - 8u] ^
            words[index - 14u] ^ words[index - 16u], 1u);
    for (uint32_t index = 0; index < 80u; ++index) {
        uint32_t function;
        uint32_t constant;
        uint32_t temporary;

        if (index < 20u) {
            function = (b & c) | (~b & d);
            constant = 0x5a827999u;
        } else if (index < 40u) {
            function = b ^ c ^ d;
            constant = 0x6ed9eba1u;
        } else if (index < 60u) {
            function = (b & c) | (b & d) | (c & d);
            constant = 0x8f1bbcdcu;
        } else {
            function = b ^ c ^ d;
            constant = 0xca62c1d6u;
        }
        temporary = sha1_rotate_left(a, 5u) + function + e +
                    constant + words[index];
        e = d;
        d = c;
        c = sha1_rotate_left(b, 30u);
        b = a;
        a = temporary;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    memset(words, 0, sizeof(words));
}

void kernel_sha1_init(kernel_sha1_context_t *context) {
    if (!context) return;
    context->state[0] = 0x67452301u;
    context->state[1] = 0xefcdab89u;
    context->state[2] = 0x98badcfeu;
    context->state[3] = 0x10325476u;
    context->state[4] = 0xc3d2e1f0u;
    context->length = 0u;
    context->block_length = 0u;
    memset(context->block, 0, sizeof(context->block));
}

void kernel_sha1_update(kernel_sha1_context_t *context,
                        const void *data, uint32_t length) {
    const uint8_t *bytes = (const uint8_t *)data;

    if (!context || (!bytes && length)) return;
    context->length += length;
    while (length) {
        uint32_t available = 64u - context->block_length;
        uint32_t copy = length < available ? length : available;

        memcpy(context->block + context->block_length, bytes, copy);
        context->block_length += copy;
        bytes += copy;
        length -= copy;
        if (context->block_length == 64u) {
            sha1_transform(context->state, context->block);
            context->block_length = 0u;
        }
    }
}

void kernel_sha1_final(kernel_sha1_context_t *context,
                       uint8_t digest[20]) {
    uint64_t bits;

    if (!context || !digest) return;
    bits = context->length * 8u;
    context->block[context->block_length++] = 0x80u;
    if (context->block_length > 56u) {
        memset(context->block + context->block_length, 0,
               64u - context->block_length);
        sha1_transform(context->state, context->block);
        context->block_length = 0u;
    }
    memset(context->block + context->block_length, 0,
           56u - context->block_length);
    for (uint32_t index = 0; index < 8u; ++index)
        context->block[63u - index] =
            (uint8_t)(bits >> (index * 8u));
    sha1_transform(context->state, context->block);
    for (uint32_t index = 0; index < 20u; ++index)
        digest[index] = (uint8_t)(
            context->state[index / 4u] >>
            (24u - (index % 4u) * 8u));
    memset(context, 0, sizeof(*context));
}
