/* SPDX-License-Identifier: MPL-2.0 */
/* Character-disk I/O adapter for imported FreeBSD storage drivers. */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/geom/geom.h"
#include "compat/freebsd/sys/bio.h"
#include "compat/freebsd/sys/conf.h"
#include "compat/freebsd/sys/malloc.h"
#include "compat/freebsd/sys/systm.h"
#include "compat/freebsd/sys/uio.h"

#define BSD_PHYSIO_EINVAL 22
#define BSD_PHYSIO_ENXIO 6

static int
bsd_physio(struct cdev *device, struct uio *uio, int io_flags)
{
    size_t maximum;
    int error = 0;

    (void)io_flags;
    if (!device || !device->si_devsw ||
        !device->si_devsw->d_strategy || !uio || uio->uio_resid < 0 ||
        uio->uio_offset < 0)
        return BSD_PHYSIO_EINVAL;
    maximum = device->si_iosize_max > 0 ?
        (size_t)device->si_iosize_max : (size_t)maxphys;
    if (maximum == 0 || maximum > (size_t)maxphys)
        maximum = (size_t)maxphys;
    if (maximum > (size_t)INT_MAX)
        maximum = (size_t)INT_MAX;
    while (uio->uio_resid != 0) {
        struct bio *bio;
        struct uio copy;
        void *buffer;
        size_t length = (size_t)uio->uio_resid;

        if (length > maximum)
            length = maximum;
        buffer = bsd_malloc(length, M_DEVBUF, M_WAITOK);
        bio = g_alloc_bio();
        if (!buffer || !bio) {
            bsd_free(buffer, M_DEVBUF);
            g_destroy_bio(bio);
            return 12;
        }
        copy = *uio;
        if (uio->uio_rw == UIO_WRITE) {
            error = uiomove(buffer, (int)length, &copy);
            if (error)
                goto complete;
        } else if (uio->uio_rw != UIO_READ) {
            error = BSD_PHYSIO_EINVAL;
            goto complete;
        }
        bio->bio_cmd = uio->uio_rw == UIO_READ ? BIO_READ : BIO_WRITE;
        bio->bio_dev = device;
        bio->bio_offset = uio->uio_offset;
        bio->bio_bcount = (long)length;
        bio->bio_length = (int64_t)length;
        bio->bio_resid = (long)length;
        bio->bio_data = buffer;
        device->si_devsw->d_strategy(bio);
        error = biowait(bio, uio->uio_rw == UIO_READ ? "physr" : "physw");
        if (error == 0 && bio->bio_resid != 0)
            error = bio->bio_error ? bio->bio_error : BSD_PHYSIO_ENXIO;
        if (error == 0 && uio->uio_rw == UIO_READ)
            error = uiomove(buffer, (int)length, &copy);
        if (error == 0)
            uioadvance(uio, length);

complete:
        g_destroy_bio(bio);
        bsd_free(buffer, M_DEVBUF);
        if (error)
            break;
    }
    return error;
}

int
physread(struct cdev *device, struct uio *uio, int io_flags)
{
    if (!uio || uio->uio_rw != UIO_READ)
        return BSD_PHYSIO_EINVAL;
    return bsd_physio(device, uio, io_flags);
}

int
physwrite(struct cdev *device, struct uio *uio, int io_flags)
{
    if (!uio || uio->uio_rw != UIO_WRITE)
        return BSD_PHYSIO_EINVAL;
    return bsd_physio(device, uio, io_flags);
}
