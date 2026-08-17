/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal hosted declarations for freestanding BSD bridge unit tests. */

#ifndef EDGEOS_BSD_BRIDGE_HOST_STDIO_H
#define EDGEOS_BSD_BRIDGE_HOST_STDIO_H

#include <stdarg.h>
#include <stddef.h>

int printf(const char *format, ...);
int dprintf(int descriptor, const char *format, ...);
int snprintf(char *buffer, size_t capacity, const char *format, ...);
int vsnprintf(char *buffer, size_t capacity, const char *format, va_list args);

#endif
