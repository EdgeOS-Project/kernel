/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD disk publication contract backed by the EdgeOS block core. */

#ifndef _GEOM_GEOM_DISK_H_
#define _GEOM_GEOM_DISK_H_

#include <stddef.h>
#include <stdint.h>
#include "../sys/bio.h"
#include "../sys/disk.h"
#include "../sys/taskqueue.h"

#define DISK_RR_UNKNOWN 0
#define DISK_RR_NON_ROTATING 1
#define DISK_RR_MIN 0x0401
#define DISK_RR_MAX 0xfffe

#define DISKFLAG_RESERVED 0x0001
#define DISKFLAG_OPEN 0x0002
#define DISKFLAG_CANDELETE 0x0004
#define DISKFLAG_CANFLUSHCACHE 0x0008
#define DISKFLAG_UNMAPPED_BIO 0x0010
#define DISKFLAG_DIRECT_COMPLETION 0x0020
#define DISKFLAG_WRITE_PROTECT 0x0100

#define DISK_VERSION_06 0x5856105f
#define DISK_VERSION DISK_VERSION_06
#define BSD_DISK_MAX_SLICES 8

struct thread;
struct disk;

typedef int disk_open_t(struct disk *);
typedef int disk_close_t(struct disk *);
typedef void disk_strategy_t(struct bio *);
typedef int disk_ioctl_t(struct disk *, unsigned long, void *, int,
    struct thread *);
typedef int dumper_t(void *, void *, int64_t, size_t);
typedef int disk_getattr_t(struct bio *);
typedef void disk_gone_t(struct disk *);

struct disk {
    unsigned int d_flags;
    const char *d_name;
    unsigned int d_unit;

    disk_open_t *d_open;
    disk_close_t *d_close;
    disk_strategy_t *d_strategy;
    disk_ioctl_t *d_ioctl;
    dumper_t *d_dump;
    disk_getattr_t *d_getattr;
    disk_gone_t *d_gone;

    unsigned int d_sectorsize;
    int64_t d_mediasize;
    unsigned int d_fwsectors;
    unsigned int d_fwheads;
    unsigned int d_maxsize;
    int64_t d_delmaxsize;
    int64_t d_stripeoffset;
    int64_t d_stripesize;
    char d_ident[DISK_IDENT_SIZE];
    char d_descr[DISK_IDENT_SIZE];
    uint16_t d_hba_vendor;
    uint16_t d_hba_device;
    uint16_t d_hba_subvendor;
    uint16_t d_hba_subdevice;
    uint16_t d_rotation_rate;
    char d_attachment[DISK_IDENT_SIZE];

    void *d_drv1;
    struct devstat *d_devstat;

    void *d_bridge_publication;
    void *d_bridge_slice_contexts[BSD_DISK_MAX_SLICES];
    void *d_bridge_slice_publications[BSD_DISK_MAX_SLICES];
    struct task d_bridge_gone_task;
    int d_bridge_error;
    uint8_t d_bridge_slice_count;
    uint8_t d_bridge_published;
    uint8_t d_bridge_destroyed;
    uint8_t d_bridge_opened;
    uint8_t d_bridge_gone;
};

struct disk *disk_alloc(void);
void disk_create(struct disk *disk, int version);
void disk_destroy(struct disk *disk);
void disk_gone(struct disk *disk);
int disk_resize(struct disk *disk, int flags);
void disk_err(struct bio *bio, const char *message, int error,
    int blocks_done);

#endif
