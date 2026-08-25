/* SPDX-License-Identifier: MPL-2.0 */
/* Small architecture-independent SHA-1 implementation. */

#ifndef EDGEOS_KERNEL_SHA1_RUNTIME_H
#define EDGEOS_KERNEL_SHA1_RUNTIME_H

#include <stdint.h>

typedef struct kernel_sha1_context {
    uint32_t state[5];
    uint64_t length;
    uint8_t block[64];
    uint32_t block_length;
} kernel_sha1_context_t;

void kernel_sha1_init(kernel_sha1_context_t *context);
void kernel_sha1_update(kernel_sha1_context_t *context,
                        const void *data, uint32_t length);
void kernel_sha1_final(kernel_sha1_context_t *context,
                       uint8_t digest[20]);

#endif
