/* SPDX-License-Identifier: MPL-2.0 */
/* SHA-256 as specified by FIPS 180-4. */

#include "kernel/sha256_runtime.h"
#include "string.h"

static uint32_t sha256_rotate_right(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32u - count));
}

static uint32_t sha256_load_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24u) |
           ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) |
           (uint32_t)bytes[3];
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t words[64];
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (uint32_t index = 0; index < 16u; ++index)
        words[index] = sha256_load_be32(block + index * 4u);
    for (uint32_t index = 16u; index < 64u; ++index) {
        uint32_t s0 = sha256_rotate_right(words[index - 15u], 7u) ^
                      sha256_rotate_right(words[index - 15u], 18u) ^
                      (words[index - 15u] >> 3u);
        uint32_t s1 = sha256_rotate_right(words[index - 2u], 17u) ^
                      sha256_rotate_right(words[index - 2u], 19u) ^
                      (words[index - 2u] >> 10u);

        words[index] = words[index - 16u] + s0 +
                       words[index - 7u] + s1;
    }
    for (uint32_t index = 0; index < 64u; ++index) {
        uint32_t s1 = sha256_rotate_right(e, 6u) ^
                      sha256_rotate_right(e, 11u) ^
                      sha256_rotate_right(e, 25u);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t temporary1 = h + s1 + choice + constants[index] +
                              words[index];
        uint32_t s0 = sha256_rotate_right(a, 2u) ^
                      sha256_rotate_right(a, 13u) ^
                      sha256_rotate_right(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = s0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
    memset(words, 0, sizeof(words));
}

void kernel_sha256_init(kernel_sha256_context_t *context) {
    if (!context) return;
    context->state[0] = 0x6a09e667u;
    context->state[1] = 0xbb67ae85u;
    context->state[2] = 0x3c6ef372u;
    context->state[3] = 0xa54ff53au;
    context->state[4] = 0x510e527fu;
    context->state[5] = 0x9b05688cu;
    context->state[6] = 0x1f83d9abu;
    context->state[7] = 0x5be0cd19u;
    context->length = 0u;
    context->block_length = 0u;
    memset(context->block, 0, sizeof(context->block));
}

void kernel_sha224_init(kernel_sha256_context_t *context) {
    if (!context) return;
    context->state[0] = 0xc1059ed8u;
    context->state[1] = 0x367cd507u;
    context->state[2] = 0x3070dd17u;
    context->state[3] = 0xf70e5939u;
    context->state[4] = 0xffc00b31u;
    context->state[5] = 0x68581511u;
    context->state[6] = 0x64f98fa7u;
    context->state[7] = 0xbefa4fa4u;
    context->length = 0u;
    context->block_length = 0u;
    memset(context->block, 0, sizeof(context->block));
}

void kernel_sha256_update(kernel_sha256_context_t *context,
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
            sha256_transform(context->state, context->block);
            context->block_length = 0u;
        }
    }
}

static void sha256_final_words(kernel_sha256_context_t *context,
                              uint8_t *digest, uint32_t length) {
    uint64_t bits;

    if (!context || !digest) return;
    bits = context->length * 8u;
    context->block[context->block_length++] = 0x80u;
    if (context->block_length > 56u) {
        memset(context->block + context->block_length, 0,
               64u - context->block_length);
        sha256_transform(context->state, context->block);
        context->block_length = 0u;
    }
    memset(context->block + context->block_length, 0,
           56u - context->block_length);
    for (uint32_t index = 0; index < 8u; ++index)
        context->block[63u - index] =
            (uint8_t)(bits >> (index * 8u));
    sha256_transform(context->state, context->block);
    for (uint32_t index = 0; index < length; ++index)
        digest[index] = (uint8_t)(
            context->state[index / 4u] >>
            (24u - (index % 4u) * 8u));
    memset(context, 0, sizeof(*context));
}

void kernel_sha256_final(kernel_sha256_context_t *context,
                         uint8_t digest[32]) {
    sha256_final_words(context, digest, 32u);
}

void kernel_sha224_final(kernel_sha256_context_t *context,
                         uint8_t digest[28]) {
    sha256_final_words(context, digest, 28u);
}
