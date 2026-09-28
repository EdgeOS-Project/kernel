/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS event-device state used by the BSD driver bridge.
 *
 * Imported drivers keep the public FreeBSD evdev API.  This private layout
 * connects that API to the native Linux-compatible EdgeOS input stream.
 */
#ifndef EDGEOS_COMPAT_FREEBSD_DEV_EVDEV_PRIVATE_H
#define EDGEOS_COMPAT_FREEBSD_DEV_EVDEV_PRIVATE_H

#include <sys/mutex.h>

#include <dev/evdev/evdev.h>
#include <dev/evdev/input.h>

#define EDGEOS_EVDEV_BITMAP_BYTES 128u

struct evdev_dev {
    char ev_name[NAMELEN];
    char ev_phys[NAMELEN];
    char ev_serial[NAMELEN];
    struct input_id ev_id;
    const struct evdev_methods *ev_methods;
    void *ev_softc;
    struct mtx ev_internal_lock;
    struct mtx *ev_state_lock;
    size_t ev_report_size;
    uid_t ev_cdev_uid;
    gid_t ev_cdev_gid;
    int ev_cdev_mode;
    uint8_t ev_prop_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_type_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_key_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_rel_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_abs_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_msc_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_led_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_snd_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_sw_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_flags[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_key_states[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_led_states[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_snd_states[EDGEOS_EVDEV_BITMAP_BYTES];
    uint8_t ev_sw_states[EDGEOS_EVDEV_BITMAP_BYTES];
    struct input_absinfo ev_absinfo[ABS_CNT];
    int ev_rep[REP_CNT];
    union evdev_mt_slot ev_mt_slots[MAX_MT_SLOTS];
    union evdev_mt_slot ev_mt_match_slots[MAX_MT_SLOTS];
    uint16_t ev_mt_active;
    uint16_t ev_mt_frame;
    int ev_mt_last_slot;
    int ev_event_index;
    int ev_registered;
    int ev_opened;
    int ev_grabbed;
    int ev_pointer;
    int ev_rel_x;
    int ev_rel_y;
    int ev_rel_wheel;
    int ev_pointer_changed;
    uint8_t ev_mouse_buttons;
};

#define EVDEV_LOCK(evdev) mtx_lock((evdev)->ev_state_lock)
#define EVDEV_UNLOCK(evdev) mtx_unlock((evdev)->ev_state_lock)
#define EVDEV_LOCK_ASSERT(evdev) ((void)(evdev))
#define EVDEV_ENTER(evdev) EVDEV_LOCK(evdev)
#define EVDEV_EXIT(evdev) EVDEV_UNLOCK(evdev)

void evdev_send_event(struct evdev_dev *, uint16_t, uint16_t, int32_t);

#endif
