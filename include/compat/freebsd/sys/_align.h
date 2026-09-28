/* SPDX-License-Identifier: MPL-2.0 */
/* Register-width alignment helpers for the EdgeOS FreeBSD driver bridge. */

#ifndef _SYS__ALIGN_H_
#define _SYS__ALIGN_H_

#define _ALIGNBYTES (sizeof(void *) - 1)
#define _ALIGN(value)                                                   \
    ((__typeof__(value))(((__UINTPTR_TYPE__)(value) + _ALIGNBYTES) &    \
    ~(__UINTPTR_TYPE__)_ALIGNBYTES))

#endif
