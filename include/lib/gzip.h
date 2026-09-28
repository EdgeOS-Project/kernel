/* SPDX-License-Identifier: MPL-2.0 */
/* Shared in-memory gzip decoder interface. */

#ifndef EDGEOS_LIB_GZIP_H
#define EDGEOS_LIB_GZIP_H

#include <stdint.h>

int edge_gzip_is_archive(const void *input, uint64_t input_size);
int edge_gzip_uncompressed_size(const void *input, uint64_t input_size,
                                uint64_t *output_size);
int edge_gzip_decompress(const void *input, uint64_t input_size,
                         uint64_t maximum_output_size, void **output,
                         uint64_t *output_size);
void edge_gzip_release(void *output);

#endif
