/* SPDX-License-Identifier: MPL-2.0 */
/* Bounds-checked LZ4 block decoder with a fixed-size history window. */

#ifndef EDGEOS_EROFS_LZ4_DECODE_H
#define EDGEOS_EROFS_LZ4_DECODE_H

#include <stdint.h>

#define EDGE_LZ4_HISTORY_SIZE 65536u

int edge_lz4_extract(const uint8_t *input, uint32_t input_size,
                     uint64_t decoded_size, uint64_t wanted_offset,
                     void *output, uint32_t wanted_size,
                     uint8_t *history, uint32_t history_size);

#endif
