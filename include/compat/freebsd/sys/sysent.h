/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD syscall-vector declarations are not required by imported drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_SYSENT_H
#define EDGEOS_COMPAT_FREEBSD_SYS_SYSENT_H

/*
 * Some mature FreeBSD drivers include this header through their control
 * path without using any syscall-vector definitions. Keep the namespace
 * available while Linux-visible syscall policy remains in EdgeOS common
 * kernel code.
 */

#endif
