/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS machine-independent support for the FreeBSD eventtimer core. */

#include <stdint.h>

#include <sys/timeet.h>

void
cpu_et_frequency(struct eventtimer *eventtimer, uint64_t frequency)
{
    if (eventtimer == NULL || frequency == 0)
        return;
    ET_LOCK();
    eventtimer->et_frequency = frequency;
    ET_UNLOCK();
}
