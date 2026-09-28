/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS LinuxKPI interrupt compatibility extensions. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_INTERRUPT_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_INTERRUPT_H_

#include_next <linux/interrupt.h>

static inline int
irq_set_affinity_and_hint(int vector, const cpumask_t *mask)
{
    return irq_set_affinity_hint(vector, mask);
}

#endif
