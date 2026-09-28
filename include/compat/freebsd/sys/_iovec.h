/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD-compatible I/O vector type for imported drivers. */

#ifndef _SYS__IOVEC_H_
#define _SYS__IOVEC_H_

#include <stddef.h>

struct iovec {
    void *iov_base;
    size_t iov_len;
};

#endif
