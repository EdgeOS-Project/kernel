/* SPDX-License-Identifier: MPL-2.0 */
/* Route imported sources to the complete upstream FreeBSD type contract. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_STDINT_H
#define EDGEOS_COMPAT_FREEBSD_SYS_STDINT_H

#if defined(BSD_BRIDGE_HOST_TEST) && defined(__STDC_HOSTED__) && \
    __STDC_HOSTED__
#include <stdint.h>
#else
#include_next <sys/stdint.h>
#endif

#endif
