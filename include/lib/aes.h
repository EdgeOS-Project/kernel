/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral AES block transform interface. */

#ifndef EDGEOS_LIB_AES_H
#define EDGEOS_LIB_AES_H

#include <stdint.h>

typedef struct edge_aes_context {
    uint8_t round_key[240];
    uint8_t rounds;
} edge_aes_context_t;

int edge_aes_initialize(edge_aes_context_t *context,
                        const uint8_t *key, uint32_t key_bytes);
void edge_aes_encrypt_block(const edge_aes_context_t *context,
                            const uint8_t input[16], uint8_t output[16]);
void edge_aes_decrypt_block(const edge_aes_context_t *context,
                            const uint8_t input[16], uint8_t output[16]);

#endif
