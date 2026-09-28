/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for imported FreeBSD select and kqueue notifications. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "compat/freebsd/sys/event.h"
#include "compat/freebsd/sys/selinfo.h"

static uint32_t g_event_count;
static long g_last_hint;

static int
test_event(struct knote *note, long hint)
{
    assert(note != 0);
    ++g_event_count;
    g_last_hint = hint;
    note->kn_data = hint;
    return 1;
}

int
main(void)
{
    struct filterops operations = {
        .f_isfd = 1,
        .f_event = test_event,
    };
    struct selinfo info = {0};
    struct knote first = {
        .kn_filter = EVFILT_READ,
        .kn_flags = EV_EOF,
        .kn_fop = &operations,
    };
    struct knote second = {
        .kn_filter = EVFILT_WRITE,
        .kn_fop = &operations,
    };
    uint64_t sequence = bsd_selinfo_change_sequence();

    knlist_init_mtx(&info.si_note, 0);
    assert(first.kn_flags == EV_EOF);
    assert(KNLIST_EMPTY(&info.si_note));
    knlist_add(&info.si_note, &first, 0);
    knlist_add(&info.si_note, &first, 0);
    assert(!KNLIST_EMPTY(&info.si_note));

    selwakeup(&info);
    assert(info.edgeos_sequence == 1);
    assert(bsd_selinfo_change_sequence() == sequence + 1);
    assert(g_event_count == 0);

    KNOTE_LOCKED(&info.si_note, 37);
    assert(g_event_count == 1);
    assert(g_last_hint == 37);
    assert(first.kn_data == 37);

    knlist_remove(&info.si_note, &first, 0);
    assert(KNLIST_EMPTY(&info.si_note));
    knlist_add(&info.si_note, &first, 0);
    knlist_add(&info.si_note, &second, 0);
    knlist_clear(&info.si_note, 0);
    assert(KNLIST_EMPTY(&info.si_note));
    assert(first.kn_fop == 0);
    assert(second.kn_fop == 0);
    knlist_destroy(&info.si_note);

    printf("bsd_bridge_selinfo_unit: PASS\n");
    return 0;
}
