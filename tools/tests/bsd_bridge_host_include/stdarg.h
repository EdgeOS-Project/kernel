/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal compiler-backed varargs for freestanding BSD bridge unit tests. */

#ifndef EDGEOS_BSD_BRIDGE_HOST_STDARG_H
#define EDGEOS_BSD_BRIDGE_HOST_STDARG_H

typedef __builtin_va_list va_list;

#define va_start(arguments, last) __builtin_va_start((arguments), (last))
#define va_end(arguments) __builtin_va_end(arguments)
#define va_arg(arguments, type) __builtin_va_arg((arguments), type)
#define va_copy(destination, source) \
    __builtin_va_copy((destination), (source))

#endif
