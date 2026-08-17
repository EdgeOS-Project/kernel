/* SPDX-License-Identifier: MPL-2.0 */
/* CPU availability interface used by imported performance drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_PMCKERN_H
#define EDGEOS_COMPAT_FREEBSD_SYS_PMCKERN_H

#include <stdint.h>

struct pmckern_map_in {
    void *pm_file;
    uintptr_t pm_address;
};

int pmc_cpu_is_disabled(int cpu);
int pmc_cpu_is_active(int cpu);
int pmc_cpu_is_present(int cpu);
int pmc_cpu_is_primary(int cpu);
unsigned int pmc_cpu_max(void);

#endif
