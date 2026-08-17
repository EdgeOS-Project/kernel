/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD-compatible UIO operation and address-space selectors. */

#ifndef _SYS__UIO_H_
#define _SYS__UIO_H_

enum uio_rw {
    UIO_READ,
    UIO_WRITE
};

enum uio_seg {
    UIO_USERSPACE,
    UIO_SYSSPACE,
    UIO_NOCOPY
};

#endif
