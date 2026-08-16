/* SPDX-License-Identifier: MPL-2.0 */
/* Shared UIO data movement for imported BSD character and storage drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/uio.h"
#include "compat/freebsd/vm/vm_page.h"

#define BSD_UIO_EFAULT 14
#define BSD_UIO_EINVAL 22

void
uioadvance(struct uio *uio, size_t length)
{
    if (!uio || length > (size_t)uio->uio_resid)
        return;
    while (length != 0 && uio->uio_iovcnt > 0) {
        struct iovec *iov = uio->uio_iov;
        size_t portion = iov->iov_len < length ? iov->iov_len : length;

        iov->iov_base = (uint8_t *)iov->iov_base + portion;
        iov->iov_len -= portion;
        uio->uio_offset += (int64_t)portion;
        uio->uio_resid -= (intptr_t)portion;
        length -= portion;
        if (iov->iov_len == 0) {
            ++uio->uio_iov;
            --uio->uio_iovcnt;
        }
    }
}

int
uiomove(void *buffer, int length, struct uio *uio)
{
    uint8_t *cursor = buffer;

    if ((!buffer && length != 0) || length < 0 || !uio ||
        uio->uio_resid < 0)
        return BSD_UIO_EINVAL;
    while (length != 0 && uio->uio_resid != 0) {
        struct iovec *iov;
        size_t portion;
        int error;

        if (!uio->uio_iov || uio->uio_iovcnt <= 0)
            return BSD_UIO_EINVAL;
        iov = uio->uio_iov;
        if (!iov->iov_base && iov->iov_len != 0)
            return BSD_UIO_EFAULT;
        if (iov->iov_len == 0) {
            ++uio->uio_iov;
            --uio->uio_iovcnt;
            continue;
        }
        portion = iov->iov_len;
        if (portion > (size_t)length)
            portion = (size_t)length;
        if (portion > (size_t)uio->uio_resid)
            portion = (size_t)uio->uio_resid;
        if (uio->uio_rw == UIO_READ) {
            error = uio->uio_segflg == UIO_USERSPACE ?
                bsd_copyout(cursor, iov->iov_base, portion) :
                bsd_copyin(cursor, iov->iov_base, portion);
        } else if (uio->uio_rw == UIO_WRITE) {
            error = uio->uio_segflg == UIO_USERSPACE ?
                bsd_copyin(iov->iov_base, cursor, portion) :
                bsd_copyin(iov->iov_base, cursor, portion);
        } else {
            return BSD_UIO_EINVAL;
        }
        if (error)
            return error;
        cursor += portion;
        length -= (int)portion;
        uioadvance(uio, portion);
    }
    return 0;
}

int
uiomove_frombuf(void *buffer, int buffer_length, struct uio *uio)
{
    int length;

    if ((!buffer && buffer_length != 0) || buffer_length < 0 || !uio ||
        uio->uio_offset < 0 || uio->uio_offset > buffer_length)
        return BSD_UIO_EINVAL;
    length = buffer_length - (int)uio->uio_offset;
    if (length > uio->uio_resid)
        length = (int)uio->uio_resid;
    return uiomove((uint8_t *)buffer + uio->uio_offset, length, uio);
}

int
uiomove_fromphys(struct vm_page *pages[], uintptr_t page_offset,
    int length, struct uio *uio)
{
    size_t page_index;
    size_t offset;

    if (!pages || page_offset >= PAGE_SIZE || length < 0 || !uio)
        return BSD_UIO_EINVAL;
    page_index = 0;
    offset = page_offset;
    while (length > 0 && uio->uio_resid > 0) {
        struct vm_page *page = pages[page_index];
        void *mapping;
        size_t portion = PAGE_SIZE - offset;
        int error;

        if (!page)
            return BSD_UIO_EFAULT;
        if (portion > (size_t)length)
            portion = (size_t)length;
        mapping = page->edgeos_page;
        if (!mapping && bsd_bus_dma_virtual_address(page->phys_addr,
            PAGE_SIZE, &mapping) != 0)
            return BSD_UIO_EFAULT;
        if (!mapping)
            return BSD_UIO_EFAULT;
        error = uiomove((uint8_t *)mapping + offset, (int)portion, uio);
        if (error != 0)
            return error;
        length -= (int)portion;
        ++page_index;
        offset = 0;
    }
    return 0;
}

int
physcopyin(void *source, uint64_t destination, size_t length)
{
    void *mapping;

    if (length == 0)
        return 0;
    if (!source || bsd_bus_dma_virtual_address(destination, length,
        &mapping) != 0 || !mapping)
        return BSD_UIO_EFAULT;
    bsd_memcpy(mapping, source, length);
    return 0;
}

int
physcopyout(uint64_t source, void *destination, size_t length)
{
    void *mapping;

    if (length == 0)
        return 0;
    if (!destination || bsd_bus_dma_virtual_address(source, length,
        &mapping) != 0 || !mapping)
        return BSD_UIO_EFAULT;
    bsd_memcpy(destination, mapping, length);
    return 0;
}
