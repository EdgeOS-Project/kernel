/* SPDX-License-Identifier: BSD-2-Clause */
/* Concurrency Kit epoch subset backed by bridge atomic reader tracking. */

#ifndef _CK_EPOCH_H_
#define _CK_EPOCH_H_

#include <stdint.h>

typedef struct ck_epoch ck_epoch_t;
typedef struct ck_epoch_record ck_epoch_record_t;

typedef struct ck_epoch_section {
    unsigned int active;
} ck_epoch_section_t;

struct ck_epoch_record {
    ck_epoch_record_t *next;
    ck_epoch_t *epoch;
    volatile unsigned int active;
};

struct ck_epoch {
    ck_epoch_record_t *records;
    volatile unsigned int readers;
};

typedef void ck_epoch_wait_cb_t(ck_epoch_t *, ck_epoch_record_t *, void *);

static inline void
ck_epoch_init(ck_epoch_t *epoch)
{
    epoch->records = 0;
    epoch->readers = 0;
}

static inline void
ck_epoch_register(ck_epoch_t *epoch, ck_epoch_record_t *record, void *context)
{
    (void)context;
    record->epoch = epoch;
    record->active = 0;
    record->next = epoch->records;
    epoch->records = record;
}

static inline void
ck_epoch_begin(ck_epoch_record_t *record, ck_epoch_section_t *section)
{
    section->active = 1;
    (void)__atomic_add_fetch(&record->active, 1u, __ATOMIC_ACQUIRE);
    (void)__atomic_add_fetch(&record->epoch->readers, 1u, __ATOMIC_ACQUIRE);
}

static inline void
ck_epoch_end(ck_epoch_record_t *record, ck_epoch_section_t *section)
{
    if (!section->active)
        return;
    section->active = 0;
    (void)__atomic_sub_fetch(&record->active, 1u, __ATOMIC_RELEASE);
    (void)__atomic_sub_fetch(&record->epoch->readers, 1u, __ATOMIC_RELEASE);
}

static inline void
ck_epoch_synchronize_wait(ck_epoch_t *epoch, ck_epoch_wait_cb_t *callback,
    void *context)
{
    while (__atomic_load_n(&epoch->readers, __ATOMIC_ACQUIRE) != 0) {
        ck_epoch_record_t *record;

        for (record = epoch->records; record; record = record->next) {
            if (__atomic_load_n(&record->active, __ATOMIC_ACQUIRE) != 0 &&
                callback)
                callback(epoch, record, context);
        }
        __atomic_signal_fence(__ATOMIC_SEQ_CST);
    }
}

#endif
