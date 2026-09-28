/* SPDX-License-Identifier: MPL-2.0 */
/* Kernel event-filter types used by imported FreeBSD character devices. */

#ifndef _SYS_EVENT_H_
#define _SYS_EVENT_H_

#include <stdint.h>

struct kevent;
struct knote;
struct knlist;
struct mtx;
struct proc;
struct thread;

#define EVFILT_READ (-1)
#define EVFILT_WRITE (-2)

#define EV_EOF 0x8000

#define KNF_LISTLOCKED 0x0001
#define KNF_NOKQLOCK 0x0002

typedef int knote_attach_t(struct knote *);
typedef void knote_detach_t(struct knote *);
typedef int knote_event_t(struct knote *, long);
typedef void knote_touch_t(struct knote *, struct kevent *, unsigned long);
typedef int knote_userdump_t(struct proc *, struct knote *, void *);
typedef int knote_copy_t(struct knote *, struct proc *);

struct filterops {
    int f_isfd;
    knote_attach_t *f_attach;
    knote_detach_t *f_detach;
    knote_event_t *f_event;
    knote_touch_t *f_touch;
    knote_userdump_t *f_userdump;
    knote_copy_t *f_copy;
};

struct knote {
    int kn_filter;
    unsigned short kn_flags;
    long kn_data;
    void *kn_hook;
    const struct filterops *kn_fop;
    struct knote *edgeos_next;
};

struct knlist {
    struct knote *edgeos_head;
    struct mtx *edgeos_mutex;
    void *edgeos_lock;
    void (*edgeos_lock_fn)(void *);
    void (*edgeos_unlock_fn)(void *);
    void (*edgeos_assert_fn)(void *, int);
};

void knote(struct knlist *list, long hint, int flags);
int knote_triv_copy(struct knote *note, struct proc *process);
void knlist_add(struct knlist *list, struct knote *note, int locked);
void knlist_remove(struct knlist *list, struct knote *note, int locked);
int knlist_empty(struct knlist *list);
void knlist_init_mtx(struct knlist *list, struct mtx *mutex);
void knlist_init(struct knlist *list, void *lock,
    void (*lock_fn)(void *), void (*unlock_fn)(void *),
    void (*assert_fn)(void *, int));
void knlist_destroy(struct knlist *list);
void knlist_cleardel(struct knlist *list, struct thread *thread,
    int locked, int delete_notes);

#define KNOTE(list, hint, flags) knote((list), (hint), (flags))
#define KNOTE_LOCKED(list, hint) knote((list), (hint), KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint) knote((list), (hint), 0)
#define KNLIST_EMPTY(list) knlist_empty(list)
#define knlist_clear(list, locked) \
    knlist_cleardel((list), (struct thread *)0, (locked), 0)

#endif
