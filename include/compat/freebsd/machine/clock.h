/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral clock delay interface for imported BSD drivers. */

#ifndef _MACHINE_CLOCK_H_
#define _MACHINE_CLOCK_H_

#include <stdint.h>
#include <edgeos/sleep.h>

extern uint64_t tsc_freq;
extern int tsc_is_invariant;

#ifndef DELAY
#define DELAY(microseconds) bsd_delay(microseconds)
#endif

#endif
