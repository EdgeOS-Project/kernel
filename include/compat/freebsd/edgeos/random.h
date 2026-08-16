/* SPDX-License-Identifier: MPL-2.0 */
/* Random-source adapter exposed by the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_RANDOM_H
#define EDGEOS_COMPAT_FREEBSD_RANDOM_H

#ifndef _SYS_TYPES_H_
#include <stddef.h>
#endif

size_t bsd_random_fill(void *buffer, size_t length);

#endif
