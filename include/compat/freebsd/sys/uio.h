/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD-compatible UIO descriptor for imported drivers. */

#ifndef _SYS_UIO_H_
#define _SYS_UIO_H_

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/sys/_iovec.h"
#include "compat/freebsd/sys/_uio.h"

struct thread;
struct vm_page;

struct uio {
    struct iovec *uio_iov;
    int uio_iovcnt;
    int64_t uio_offset;
    intptr_t uio_resid;
    enum uio_seg uio_segflg;
    enum uio_rw uio_rw;
    struct thread *uio_td;
};

#define UIO_MAXIOV 1024

void uioadvance(struct uio *uio, size_t length);
int uiomove(void *buffer, int length, struct uio *uio);
int uiomove_frombuf(void *buffer, int buffer_length, struct uio *uio);
int uiomove_fromphys(struct vm_page *pages[], uintptr_t page_offset,
    int length, struct uio *uio);
int physcopyin(void *source, uint64_t destination, size_t length);
int physcopyout(uint64_t source, void *destination, size_t length);

#endif
