/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent ELF ABI validation.
 * Copyright (c) EdgeOS Contributors.
 */

#include "elf/elf_abi.h"

int edge_elf_file_range_valid(uint64_t file_size, uint64_t offset,
                              uint64_t length) {
    /*
     * A zero-sized file contribution is valid regardless of p_offset.  Linkers
     * use this for pure-BSS PT_LOAD records whose memory image has no bytes in
     * the executable.  Non-empty ranges must fit without unsigned overflow.
     */
    if (!length) return 1;
    return offset <= file_size && length <= file_size - offset;
}
