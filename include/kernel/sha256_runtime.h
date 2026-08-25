/* SPDX-License-Identifier: MPL-2.0 */
/* Small architecture-independent SHA-256 implementation. */

#ifndef EDGEOS_KERNEL_SHA256_RUNTIME_H
#define EDGEOS_KERNEL_SHA256_RUNTIME_H

#include <stdint.h>

typedef struct kernel_sha256_context {
    uint32_t state[8];
    uint64_t length;
    uint8_t block[64];
    uint32_t block_length;
} kernel_sha256_context_t;

void kernel_sha256_init(kernel_sha256_context_t *context);
void kernel_sha256_update(kernel_sha256_context_t *context,
                          const void *data, uint32_t length);
void kernel_sha256_final(kernel_sha256_context_t *context,
                         uint8_t digest[32]);

#endif
