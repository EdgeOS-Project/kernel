/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD BIO contract used by imported storage drivers. */

#ifndef _SYS_BIO_H_
#define _SYS_BIO_H_

#include <stdint.h>
#include <sys/queue.h>

#define BIO_READ 0x01
#define BIO_WRITE 0x02
#define BIO_DELETE 0x03
#define BIO_GETATTR 0x04
#define BIO_FLUSH 0x05
#define BIO_CMD0 0x06
#define BIO_CMD1 0x07
#define BIO_CMD2 0x08

#define BIO_ERROR 0x01
#define BIO_DONE 0x02
#define BIO_ONQUEUE 0x04
#define BIO_ORDERED 0x08
#define BIO_UNMAPPED 0x10
#define BIO_TRANSIENT_MAPPING 0x20
#define BIO_VLIST 0x40

struct disk;
struct vm_page;
struct cdev;
struct devstat;
struct g_provider;

struct bio {
    uint16_t bio_cmd;
    uint16_t bio_flags;
    struct disk *bio_disk;
    struct cdev *bio_dev;
    struct g_provider *bio_to;
    struct bio *bio_parent;
    int64_t bio_offset;
    int64_t bio_pblkno;
    long bio_bcount;
    char *bio_data;
    struct vm_page **bio_ma;
    int bio_ma_offset;
    int bio_ma_n;
    long bio_resid;
    void (*bio_done)(struct bio *);
    void *bio_driver1;
    void *bio_driver2;
    TAILQ_ENTRY(bio) bio_queue;
    const char *bio_attribute;
    int64_t bio_length;
    int64_t bio_completed;
    int bio_error;
    volatile unsigned int bio_children;
    volatile unsigned int bio_inbed;
};

TAILQ_HEAD(bio_queue, bio);

struct bio_queue_head {
    struct bio_queue queue;
    int64_t last_offset;
    struct bio *insert_point;
    int total;
    int batched;
};

void biodone(struct bio *bio);
void biofinish(struct bio *bio, void *statistics, int error);
int biowait(struct bio *bio, const char *wait_message);
void bioq_init(struct bio_queue_head *queue);
void bioq_flush(struct bio_queue_head *queue, struct devstat *statistics,
    int error);
void bioq_insert_head(struct bio_queue_head *queue, struct bio *bio);
void bioq_insert_tail(struct bio_queue_head *queue, struct bio *bio);
void bioq_disksort(struct bio_queue_head *queue, struct bio *bio);
void bioq_remove(struct bio_queue_head *queue, struct bio *bio);
struct bio *bioq_first(struct bio_queue_head *queue);
struct bio *bioq_takefirst(struct bio_queue_head *queue);

#endif
