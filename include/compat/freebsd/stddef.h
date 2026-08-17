/* SPDX-License-Identifier: MPL-2.0 */
/* Standard definitions backed by the imported FreeBSD kernel type model. */
#ifndef EDGEOS_COMPAT_FREEBSD_STDDEF_H
#define EDGEOS_COMPAT_FREEBSD_STDDEF_H

#include <sys/_null.h>
#include <sys/_offsetof.h>
#include <sys/_types.h>

#ifndef _SIZE_T_DECLARED
typedef __size_t size_t;
#define _SIZE_T_DECLARED
#endif

#ifndef _PTRDIFF_T_DECLARED
typedef __ptrdiff_t ptrdiff_t;
#define _PTRDIFF_T_DECLARED
#endif

#ifndef _WCHAR_T_DECLARED
typedef ___wchar_t wchar_t;
#define _WCHAR_T_DECLARED
#endif

#endif
