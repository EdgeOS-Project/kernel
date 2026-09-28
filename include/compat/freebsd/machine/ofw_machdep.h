/* SPDX-License-Identifier: MPL-2.0 */
/* Machine-independent OFW types used by the BSD driver bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_OFW_MACHDEP_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_OFW_MACHDEP_H

#include <stdint.h>
#include "../vm/vm.h"

typedef uint32_t cell_t;

struct mem_region {
    vm_offset_t mr_start;
    vm_size_t mr_size;
};

#endif
