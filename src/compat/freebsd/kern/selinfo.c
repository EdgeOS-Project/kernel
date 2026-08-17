/* SPDX-License-Identifier: MPL-2.0 */
/* Shared select and kqueue notification lists for imported BSD drivers. */

#include <stddef.h>

#include "compat/freebsd/sys/selinfo.h"

static volatile uint64_t g_selinfo_change_sequence;

void
knlist_init_mtx(struct knlist *list, struct mtx *mutex)
{
    if (!list)
        return;
    list->edgeos_head = 0;
    list->edgeos_mutex = mutex;
}

void
knlist_add(struct knlist *list, struct knote *note, int locked)
{
    struct knote *current;

    (void)locked;
    if (!list || !note)
        return;
    for (current = list->edgeos_head; current; current = current->edgeos_next) {
        if (current == note)
            return;
    }
    note->edgeos_next = list->edgeos_head;
    list->edgeos_head = note;
}

void
knlist_remove(struct knlist *list, struct knote *note, int locked)
{
    struct knote **cursor;

    (void)locked;
    if (!list || !note)
        return;
    cursor = &list->edgeos_head;
    while (*cursor && *cursor != note)
        cursor = &(*cursor)->edgeos_next;
    if (*cursor == note) {
        *cursor = note->edgeos_next;
        note->edgeos_next = 0;
    }
}

void
knlist_cleardel(struct knlist *list, struct thread *thread,
    int locked, int delete_notes)
{
    struct knote *note;

    (void)thread;
    (void)locked;
    (void)delete_notes;
    if (!list)
        return;
    note = list->edgeos_head;
    list->edgeos_head = 0;
    while (note) {
        struct knote *next = note->edgeos_next;

        note->edgeos_next = 0;
        note->kn_fop = 0;
        note->kn_hook = 0;
        note = next;
    }
}

void
knlist_destroy(struct knlist *list)
{
    if (!list)
        return;
    knlist_cleardel(list, 0, 0, 0);
    list->edgeos_mutex = 0;
}

int
knote_triv_copy(struct knote *note, struct proc *process)
{
    (void)process;
    if (!note)
        return 22;
    return 0;
}

void
bsd_knote_notify(struct knlist *list, long hint)
{
    struct knote *note;

    if (!list)
        return;
    for (note = list->edgeos_head; note; note = note->edgeos_next) {
        if (note->kn_fop && note->kn_fop->f_event)
            (void)note->kn_fop->f_event(note, hint);
    }
}

void
knote(struct knlist *list, long hint, int flags)
{
    (void)flags;
    bsd_knote_notify(list, hint);
}

int
knlist_empty(struct knlist *list)
{
    return !list || list->edgeos_head == 0;
}

uint64_t
bsd_selinfo_change_sequence(void)
{
    return __atomic_load_n(
        &g_selinfo_change_sequence, __ATOMIC_ACQUIRE);
}

void
selrecord(struct thread *thread, struct selinfo *info)
{
    (void)thread;
    (void)info;
}

void
selwakeup(struct selinfo *info)
{
    if (!info)
        return;
    (void)__atomic_add_fetch(&info->edgeos_sequence, 1,
        __ATOMIC_RELEASE);
    (void)__atomic_add_fetch(&g_selinfo_change_sequence, 1,
        __ATOMIC_RELEASE);
}

void
selwakeuppri(struct selinfo *info, int priority)
{
    (void)priority;
    selwakeup(info);
}

void
seldrain(struct selinfo *info)
{
    if (!info)
        return;
    knlist_cleardel(&info->si_note, 0, 0, 0);
}
