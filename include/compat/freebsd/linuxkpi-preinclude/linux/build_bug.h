/* SPDX-License-Identifier: BSD-2-Clause */
/* GCC-compatible compile-time assertion expressions for FreeBSD LinuxKPI. */

#ifndef EDGEOS_LINUXKPI_PREINCLUDE_BUILD_BUG_H
#define EDGEOS_LINUXKPI_PREINCLUDE_BUILD_BUG_H

#include_next <linux/build_bug.h>

/*
 * GCC does not treat a short-circuited expression containing a runtime
 * operand as an integer constant expression for a bit-field width.  Select
 * the diagnostic array only when the complete predicate is constant.
 */
#undef BUILD_BUG_ON_ZERO
#define BUILD_BUG_ON_ZERO(expression) \
    __builtin_choose_expr(__builtin_constant_p(expression), \
        ((int)sizeof(char[1 - 2 * !!(expression)]) - 1), 0)

#endif
