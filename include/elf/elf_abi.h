/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ELF_ABI_H
#define EDGEOS_ELF_ABI_H

#include <stdint.h>

/* Validate the file-backed portion of an ELF program header. */
int edge_elf_file_range_valid(uint64_t file_size, uint64_t offset,
                              uint64_t length);

#endif
