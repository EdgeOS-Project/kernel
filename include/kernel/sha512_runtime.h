/* SPDX-License-Identifier: MPL-2.0 */
/* Small architecture-independent SHA-384 and SHA-512 implementation. */

#ifndef EDGEOS_KERNEL_SHA512_RUNTIME_H
#define EDGEOS_KERNEL_SHA512_RUNTIME_H

#include <stdint.h>

typedef struct kernel_sha512_context {
    uint64_t state[8];
    uint64_t length_low;
    uint64_t length_high;
    uint8_t block[128];
    uint32_t block_length;
} kernel_sha512_context_t;

void kernel_sha512_init(kernel_sha512_context_t *context);
void kernel_sha384_init(kernel_sha512_context_t *context);
void kernel_sha512_update(kernel_sha512_context_t *context,
                          const void *data, uint32_t length);
void kernel_sha512_final(kernel_sha512_context_t *context,
                         uint8_t digest[64]);
void kernel_sha384_final(kernel_sha512_context_t *context,
                         uint8_t digest[48]);

#endif
