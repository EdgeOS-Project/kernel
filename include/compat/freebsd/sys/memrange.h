/* SPDX-License-Identifier: BSD-2-Clause */
/* Memory-range attributes are only required by the 32-bit LinuxKPI path. */

#ifndef _SYS_MEMRANGE_H_
#define _SYS_MEMRANGE_H_

#define MDF_WRITECOMBINE (1 << 1)
#define MEMRANGE_SET_UPDATE 0
#define MEMRANGE_SET_REMOVE 1

struct mem_range_desc {
    uint64_t mr_base;
    uint64_t mr_len;
    int mr_flags;
    char mr_owner[8];
};

int mem_range_attr_set(struct mem_range_desc *descriptor, int *action);

#endif
