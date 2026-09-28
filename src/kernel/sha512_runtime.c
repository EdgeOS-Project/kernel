/* SPDX-License-Identifier: MPL-2.0 */
/* SHA-384 and SHA-512 as specified by FIPS 180-4. */

#include "kernel/sha512_runtime.h"
#include "string.h"

static uint64_t sha512_rotate_right(uint64_t value, uint32_t count) {
    return (value >> count) | (value << (64u - count));
}

static uint64_t sha512_load_be64(const uint8_t *bytes) {
    uint64_t value = 0u;

    for (uint32_t index = 0; index < 8u; ++index)
        value = (value << 8u) | bytes[index];
    return value;
}

static void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    static const uint64_t constants[80] = {
        0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
        0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
        0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
        0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
        0xd807aa98a3030242ull, 0x12835b0145706fbeull,
        0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
        0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
        0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
        0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
        0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
        0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
        0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
        0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
        0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
        0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
        0x06ca6351e003826full, 0x142929670a0e6e70ull,
        0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
        0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
        0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
        0x81c2c92e47edaee6ull, 0x92722c851482353bull,
        0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
        0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
        0xd192e819d6ef5218ull, 0xd69906245565a910ull,
        0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
        0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
        0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
        0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
        0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
        0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
        0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
        0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
        0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
        0xca273eceea26619cull, 0xd186b8c721c0c207ull,
        0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
        0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
        0x113f9804bef90daeull, 0x1b710b35131c471bull,
        0x28db77f523047d84ull, 0x32caab7b40c72493ull,
        0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
        0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
        0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
    };
    uint64_t words[80];
    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];

    for (uint32_t index = 0; index < 16u; ++index)
        words[index] = sha512_load_be64(block + index * 8u);
    for (uint32_t index = 16u; index < 80u; ++index) {
        uint64_t s0 = sha512_rotate_right(words[index - 15u], 1u) ^
                      sha512_rotate_right(words[index - 15u], 8u) ^
                      (words[index - 15u] >> 7u);
        uint64_t s1 = sha512_rotate_right(words[index - 2u], 19u) ^
                      sha512_rotate_right(words[index - 2u], 61u) ^
                      (words[index - 2u] >> 6u);

        words[index] = words[index - 16u] + s0 +
                       words[index - 7u] + s1;
    }
    for (uint32_t index = 0; index < 80u; ++index) {
        uint64_t s1 = sha512_rotate_right(e, 14u) ^
                      sha512_rotate_right(e, 18u) ^
                      sha512_rotate_right(e, 41u);
        uint64_t choice = (e & f) ^ (~e & g);
        uint64_t temporary1 = h + s1 + choice + constants[index] +
                              words[index];
        uint64_t s0 = sha512_rotate_right(a, 28u) ^
                      sha512_rotate_right(a, 34u) ^
                      sha512_rotate_right(a, 39u);
        uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temporary2 = s0 + majority;

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

static void sha512_reset(kernel_sha512_context_t *context,
                         const uint64_t initial[8]) {
    if (!context) return;
    memcpy(context->state, initial, sizeof(context->state));
    context->length_low = 0u;
    context->length_high = 0u;
    context->block_length = 0u;
    memset(context->block, 0, sizeof(context->block));
}

void kernel_sha512_init(kernel_sha512_context_t *context) {
    static const uint64_t initial[8] = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
        0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
        0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
    };
    sha512_reset(context, initial);
}

void kernel_sha384_init(kernel_sha512_context_t *context) {
    static const uint64_t initial[8] = {
        0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
        0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
        0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
        0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
    };
    sha512_reset(context, initial);
}

void kernel_sha512_update(kernel_sha512_context_t *context,
                          const void *data, uint32_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t previous;

    if (!context || (!bytes && length)) return;
    previous = context->length_low;
    context->length_low += length;
    if (context->length_low < previous) ++context->length_high;
    while (length) {
        uint32_t available = 128u - context->block_length;
        uint32_t copy = length < available ? length : available;

        memcpy(context->block + context->block_length, bytes, copy);
        context->block_length += copy;
        bytes += copy;
        length -= copy;
        if (context->block_length == 128u) {
            sha512_transform(context->state, context->block);
            context->block_length = 0u;
        }
    }
}

static void sha512_final_words(kernel_sha512_context_t *context,
                               uint8_t *digest, uint32_t length) {
    uint64_t bits_low;
    uint64_t bits_high;

    if (!context || !digest) return;
    bits_low = context->length_low << 3u;
    bits_high = (context->length_high << 3u) |
                (context->length_low >> 61u);
    context->block[context->block_length++] = 0x80u;
    if (context->block_length > 112u) {
        memset(context->block + context->block_length, 0,
               128u - context->block_length);
        sha512_transform(context->state, context->block);
        context->block_length = 0u;
    }
    memset(context->block + context->block_length, 0,
           112u - context->block_length);
    for (uint32_t index = 0; index < 8u; ++index) {
        context->block[119u - index] =
            (uint8_t)(bits_high >> (index * 8u));
        context->block[127u - index] =
            (uint8_t)(bits_low >> (index * 8u));
    }
    sha512_transform(context->state, context->block);
    for (uint32_t index = 0; index < length; ++index)
        digest[index] = (uint8_t)(
            context->state[index / 8u] >>
            (56u - (index % 8u) * 8u));
    memset(context, 0, sizeof(*context));
}

void kernel_sha512_final(kernel_sha512_context_t *context,
                         uint8_t digest[64]) {
    sha512_final_words(context, digest, 64u);
}

void kernel_sha384_final(kernel_sha512_context_t *context,
                         uint8_t digest[48]) {
    sha512_final_words(context, digest, 48u);
}
