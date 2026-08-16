/* SPDX-License-Identifier: MPL-2.0 */
/* Compile-only coverage for the ARM64 COFF variable-argument bridge. */

#include <stdarg.h>

int
bsd_bridge_arm64_varargs_probe(const char *format, ...)
{
    va_list arguments;
    int value;

    (void)format;
    va_start(arguments, format);
    value = va_arg(arguments, int);
    va_end(arguments);
    return value;
}
