/* SPDX-License-Identifier: BSD-3-Clause */
/* EdgeOS currently exposes a no-swap pager contract to imported drivers. */

#ifndef _VM_SWAP_PAGER_H_
#define _VM_SWAP_PAGER_H_

static inline void
swap_pager_status(int *total, int *used)
{
    if (total)
        *total = 0;
    if (used)
        *used = 0;
}

#endif
