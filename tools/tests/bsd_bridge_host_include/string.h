/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal hosted declarations for freestanding BSD bridge unit tests. */

#ifndef EDGEOS_BSD_BRIDGE_HOST_STRING_H
#define EDGEOS_BSD_BRIDGE_HOST_STRING_H

#include <stddef.h>

void *memcpy(void *destination, const void *source, size_t length);
void *memset(void *destination, int value, size_t length);

#endif
