/* SPDX-License-Identifier: MPL-2.0 */
/*
 * FreeBSD evdev API adapter for the native EdgeOS Linux-compatible input ABI.
 */

#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <dev/evdev/evdev.h>
#include <dev/evdev/evdev_private.h>
#include <dev/evdev/input.h>

#include "kernel/input_device.h"
#include "keyboard.h"

int evdev_rcpt_mask = EVDEV_RCPT_HW_MOUSE | EVDEV_RCPT_HW_KBD;
int evdev_sysmouse_t_axis = EVDEV_SYSMOUSE_T_AXIS_UMS;

static int
evdev_bitmap_test(const uint8_t *bitmap, uint16_t bit)
{
    if (bitmap == NULL || bit >= EDGEOS_EVDEV_BITMAP_BYTES * 8u)
        return (0);
    return ((bitmap[bit >> 3] & (uint8_t)(1u << (bit & 7u))) != 0);
}

static void
evdev_bitmap_set(uint8_t *bitmap, uint16_t bit)
{
    if (bitmap == NULL || bit >= EDGEOS_EVDEV_BITMAP_BYTES * 8u)
        return;
    bitmap[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
}

static void
evdev_bitmap_clear(uint8_t *bitmap, uint16_t bit)
{
    if (bitmap == NULL || bit >= EDGEOS_EVDEV_BITMAP_BYTES * 8u)
        return;
    bitmap[bit >> 3] &= (uint8_t)~(1u << (bit & 7u));
}

static void
evdev_copy_text(char destination[NAMELEN], const char *source)
{
    if (source == NULL)
        source = "";
    (void)strlcpy(destination, source, NAMELEN);
}

static int
evdev_lock_if_needed(struct evdev_dev *evdev)
{
    if (evdev == NULL || evdev->ev_state_lock == NULL ||
        mtx_owned(evdev->ev_state_lock))
        return (0);
    mtx_lock(evdev->ev_state_lock);
    return (1);
}

static void
evdev_unlock_if_needed(struct evdev_dev *evdev, int locked)
{
    if (locked)
        mtx_unlock(evdev->ev_state_lock);
}

static int
evdev_pointer_key(uint16_t code)
{
    return (code >= BTN_MOUSE && code <= BTN_TASK) ||
        code == BTN_TOUCH || code == BTN_TOOL_FINGER;
}

static int
evdev_is_pointer(const struct evdev_dev *evdev)
{
    uint16_t code;

    if (evdev_bitmap_test(evdev->ev_type_flags, EV_REL) ||
        evdev_bitmap_test(evdev->ev_type_flags, EV_ABS))
        return (1);
    for (code = BTN_MOUSE; code <= BTN_TASK; ++code) {
        if (evdev_bitmap_test(evdev->ev_key_flags, code))
            return (1);
    }
    return (evdev_bitmap_test(evdev->ev_key_flags, BTN_TOUCH) ||
        evdev_bitmap_test(evdev->ev_key_flags, BTN_TOOL_FINGER));
}

static uint8_t
evdev_key_to_set1(uint16_t code, int *extended)
{
    *extended = 0;
    switch (code) {
    case KEY_HOME:
        *extended = 1;
        return (0x47);
    case KEY_UP:
        *extended = 1;
        return (0x48);
    case KEY_PAGEUP:
        *extended = 1;
        return (0x49);
    case KEY_LEFT:
        *extended = 1;
        return (0x4b);
    case KEY_RIGHT:
        *extended = 1;
        return (0x4d);
    case KEY_END:
        *extended = 1;
        return (0x4f);
    case KEY_DOWN:
        *extended = 1;
        return (0x50);
    case KEY_PAGEDOWN:
        *extended = 1;
        return (0x51);
    case KEY_INSERT:
        *extended = 1;
        return (0x52);
    case KEY_DELETE:
        *extended = 1;
        return (0x53);
    case KEY_KPENTER:
        *extended = 1;
        return (0x1c);
    case KEY_RIGHTCTRL:
        *extended = 1;
        return (0x1d);
    case KEY_KPSLASH:
        *extended = 1;
        return (0x35);
    case KEY_RIGHTALT:
        *extended = 1;
        return (0x38);
    case KEY_LEFTMETA:
        *extended = 1;
        return (0x5b);
    case KEY_RIGHTMETA:
        *extended = 1;
        return (0x5c);
    case KEY_MENU:
        *extended = 1;
        return (0x5d);
    default:
        return (code > KEY_RESERVED && code < 0x80u ?
            (uint8_t)code : 0);
    }
}

static void
evdev_emit_console_key(uint16_t code, int32_t value)
{
    uint8_t scan;
    int extended;

    if (value == 2)
        return;
    scan = evdev_key_to_set1(code, &extended);
    if (scan == 0)
        return;
    if (extended)
        keyboard_emit_scancode_console_only(0xe0);
    keyboard_emit_scancode_console_only(
        value != 0 ? scan : (uint8_t)(scan | 0x80u));
}

static void
evdev_update_mouse_compat(struct evdev_dev *evdev, uint16_t type,
    uint16_t code, int32_t value)
{
    uint8_t mask = 0;

    if (type == EV_REL) {
        if (code == REL_X) {
            evdev->ev_rel_x += value;
            evdev->ev_pointer_changed |= value != 0;
        } else if (code == REL_Y) {
            evdev->ev_rel_y += value;
            evdev->ev_pointer_changed |= value != 0;
        } else if (code == REL_WHEEL) {
            evdev->ev_rel_wheel += value;
            evdev->ev_pointer_changed |= value != 0;
        }
        return;
    }
    if (type == EV_KEY) {
        if (code == BTN_LEFT)
            mask = 0x01u;
        else if (code == BTN_RIGHT)
            mask = 0x02u;
        else if (code == BTN_MIDDLE)
            mask = 0x04u;
        if (mask != 0) {
            uint8_t previous = evdev->ev_mouse_buttons;
            if (value != 0)
                evdev->ev_mouse_buttons |= mask;
            else
                evdev->ev_mouse_buttons &= (uint8_t)~mask;
            evdev->ev_pointer_changed |=
                previous != evdev->ev_mouse_buttons;
        }
        return;
    }
    if (type == EV_SYN && code == SYN_REPORT) {
        if (evdev->ev_pointer_changed) {
            keyboard_mouse_emit_compat_packet_ex(evdev->ev_rel_x,
                -evdev->ev_rel_y, evdev->ev_rel_wheel,
                evdev->ev_mouse_buttons, evdev->ev_rel_wheel != 0);
        }
        evdev->ev_rel_x = 0;
        evdev->ev_rel_y = 0;
        evdev->ev_rel_wheel = 0;
        evdev->ev_pointer_changed = 0;
        evdev->ev_mt_frame = 0;
    }
}

struct evdev_dev *
evdev_alloc(void)
{
    struct evdev_dev *evdev;
    int slot;

    evdev = bsd_malloc(sizeof(*evdev), M_DEVBUF, M_WAITOK | M_ZERO);
    if (evdev == NULL)
        return (NULL);
    mtx_init(&evdev->ev_internal_lock, "EdgeOS evdev", NULL, MTX_DEF);
    evdev->ev_state_lock = &evdev->ev_internal_lock;
    evdev->ev_event_index = -1;
    evdev->ev_mt_last_slot = -1;
    evdev->ev_rep[REP_DELAY] = 250;
    evdev->ev_rep[REP_PERIOD] = 33;
    for (slot = 0; slot < MAX_MT_SLOTS; ++slot)
        evdev->ev_mt_slots[slot].id = -1;
    return (evdev);
}

void
evdev_free(struct evdev_dev *evdev)
{
    if (evdev == NULL)
        return;
    if (evdev->ev_registered)
        (void)evdev_unregister(evdev);
    mtx_destroy(&evdev->ev_internal_lock);
    bsd_free(evdev, M_DEVBUF);
}

void
evdev_set_name(struct evdev_dev *evdev, const char *name)
{
    if (evdev != NULL)
        evdev_copy_text(evdev->ev_name, name);
}

void
evdev_set_id(struct evdev_dev *evdev, uint16_t bustype, uint16_t vendor,
    uint16_t product, uint16_t version)
{
    if (evdev == NULL)
        return;
    evdev->ev_id.bustype = bustype;
    evdev->ev_id.vendor = vendor;
    evdev->ev_id.product = product;
    evdev->ev_id.version = version;
}

void
evdev_set_phys(struct evdev_dev *evdev, const char *name)
{
    if (evdev != NULL)
        evdev_copy_text(evdev->ev_phys, name);
}

void
evdev_set_serial(struct evdev_dev *evdev, const char *serial)
{
    if (evdev != NULL)
        evdev_copy_text(evdev->ev_serial, serial);
}

void
evdev_set_methods(struct evdev_dev *evdev, void *softc,
    const struct evdev_methods *methods)
{
    if (evdev == NULL)
        return;
    evdev->ev_softc = softc;
    evdev->ev_methods = methods;
}

static int
evdev_register_common(struct evdev_dev *evdev)
{
    input_device_description_t description;
    uint32_t event_index;
    int error;
    int locked;

    if (evdev == NULL || evdev->ev_registered || evdev->ev_name[0] == '\0')
        return (EINVAL);
    memset(&description, 0, sizeof(description));
    evdev->ev_pointer = evdev_is_pointer(evdev);
    evdev->ev_event_index = evdev->ev_pointer ?
        (int)EDGE_INPUT_POINTER : (int)EDGE_INPUT_KEYBOARD;
    description.name = evdev->ev_name;
    description.physical_path = evdev->ev_phys;
    description.driver = "bsd-evdev";
    description.role = evdev->ev_pointer ?
        EDGE_INPUT_ROLE_POINTER : EDGE_INPUT_ROLE_KEYBOARD;
    description.bustype = evdev->ev_id.bustype;
    description.vendor = evdev->ev_id.vendor;
    description.product = evdev->ev_id.product;
    description.version = evdev->ev_id.version;
    memcpy(description.properties, evdev->ev_prop_flags,
        sizeof(description.properties));
    memcpy(description.event_bits, evdev->ev_type_flags,
        sizeof(description.event_bits));
    memcpy(description.key_bits, evdev->ev_key_flags,
        sizeof(description.key_bits));
    memcpy(description.relative_bits, evdev->ev_rel_flags,
        sizeof(description.relative_bits));
    memcpy(description.absolute_bits, evdev->ev_abs_flags,
        sizeof(description.absolute_bits));
    for (uint16_t axis = 0; axis < ABS_CNT &&
        axis < EDGE_INPUT_ABS_AXES; ++axis) {
        description.absolute[axis].value = evdev->ev_absinfo[axis].value;
        description.absolute[axis].minimum =
            evdev->ev_absinfo[axis].minimum;
        description.absolute[axis].maximum =
            evdev->ev_absinfo[axis].maximum;
        description.absolute[axis].fuzz = evdev->ev_absinfo[axis].fuzz;
        description.absolute[axis].flat = evdev->ev_absinfo[axis].flat;
        description.absolute[axis].resolution =
            evdev->ev_absinfo[axis].resolution;
    }
    description.repeat_delay_ms = (uint32_t)evdev->ev_rep[REP_DELAY];
    description.repeat_period_ms = (uint32_t)evdev->ev_rep[REP_PERIOD];
    error = input_device_register_available(
        (uint32_t)evdev->ev_event_index, &description, evdev,
        &event_index);
    if (error != 0) {
        evdev->ev_event_index = -1;
        return (-error);
    }
    evdev->ev_event_index = (int)event_index;
    evdev->ev_registered = 1;
    if (evdev->ev_methods != NULL && evdev->ev_methods->ev_open != NULL) {
        locked = evdev_lock_if_needed(evdev);
        error = evdev->ev_methods->ev_open(evdev);
        evdev_unlock_if_needed(evdev, locked);
        if (error != 0) {
            (void)input_device_unregister(
                (uint32_t)evdev->ev_event_index, evdev);
            evdev->ev_registered = 0;
            evdev->ev_event_index = -1;
            return (error);
        }
        evdev->ev_opened = 1;
    }
    return (0);
}

int
evdev_register(struct evdev_dev *evdev)
{
    if (evdev == NULL)
        return (EINVAL);
    evdev->ev_state_lock = &evdev->ev_internal_lock;
    return (evdev_register_common(evdev));
}

int
evdev_register_mtx(struct evdev_dev *evdev, struct mtx *mutex)
{
    if (evdev == NULL || mutex == NULL)
        return (EINVAL);
    evdev->ev_state_lock = mutex;
    return (evdev_register_common(evdev));
}

int
evdev_unregister(struct evdev_dev *evdev)
{
    int error = 0;
    int locked;

    if (evdev == NULL || !evdev->ev_registered)
        return (ENXIO);
    if (evdev->ev_opened && evdev->ev_methods != NULL &&
        evdev->ev_methods->ev_close != NULL) {
        locked = evdev_lock_if_needed(evdev);
        error = evdev->ev_methods->ev_close(evdev);
        evdev_unlock_if_needed(evdev, locked);
    }
    evdev->ev_opened = 0;
    (void)input_device_unregister((uint32_t)evdev->ev_event_index, evdev);
    evdev->ev_registered = 0;
    evdev->ev_event_index = -1;
    return (error);
}

void *
evdev_get_softc(struct evdev_dev *evdev)
{
    return (evdev != NULL ? evdev->ev_softc : NULL);
}

bool
evdev_is_grabbed(struct evdev_dev *evdev)
{
    return (evdev != NULL && evdev->ev_grabbed != 0);
}

void
evdev_support_prop(struct evdev_dev *evdev, uint16_t prop)
{
    if (evdev != NULL && prop < INPUT_PROP_CNT)
        evdev_bitmap_set(evdev->ev_prop_flags, prop);
}

void
evdev_support_event(struct evdev_dev *evdev, uint16_t type)
{
    if (evdev != NULL && type < EV_CNT)
        evdev_bitmap_set(evdev->ev_type_flags, type);
}

void
evdev_support_key(struct evdev_dev *evdev, uint16_t code)
{
    if (evdev == NULL || code >= KEY_CNT)
        return;
    evdev_support_event(evdev, EV_KEY);
    evdev_bitmap_set(evdev->ev_key_flags, code);
}

void
evdev_support_rel(struct evdev_dev *evdev, uint16_t code)
{
    if (evdev == NULL || code >= REL_CNT)
        return;
    evdev_support_event(evdev, EV_REL);
    evdev_bitmap_set(evdev->ev_rel_flags, code);
}

void
evdev_support_abs(struct evdev_dev *evdev, uint16_t code, int32_t minimum,
    int32_t maximum, int32_t fuzz, int32_t flat, int32_t resolution)
{
    if (evdev == NULL || code >= ABS_CNT)
        return;
    evdev_support_event(evdev, EV_ABS);
    evdev_bitmap_set(evdev->ev_abs_flags, code);
    evdev->ev_absinfo[code].minimum = minimum;
    evdev->ev_absinfo[code].maximum = maximum;
    evdev->ev_absinfo[code].fuzz = fuzz;
    evdev->ev_absinfo[code].flat = flat;
    evdev->ev_absinfo[code].resolution = resolution;
}

void
evdev_support_msc(struct evdev_dev *evdev, uint16_t code)
{
    if (evdev == NULL || code >= MSC_CNT)
        return;
    evdev_support_event(evdev, EV_MSC);
    evdev_bitmap_set(evdev->ev_msc_flags, code);
}

void
evdev_support_led(struct evdev_dev *evdev, uint16_t code)
{
    if (evdev == NULL || code >= LED_CNT)
        return;
    evdev_support_event(evdev, EV_LED);
    evdev_bitmap_set(evdev->ev_led_flags, code);
}

void
evdev_support_snd(struct evdev_dev *evdev, uint16_t code)
{
    if (evdev == NULL || code >= SND_CNT)
        return;
    evdev_support_event(evdev, EV_SND);
    evdev_bitmap_set(evdev->ev_snd_flags, code);
}

void
evdev_support_sw(struct evdev_dev *evdev, uint16_t code)
{
    if (evdev == NULL || code >= SW_CNT)
        return;
    evdev_support_event(evdev, EV_SW);
    evdev_bitmap_set(evdev->ev_sw_flags, code);
}

void
evdev_set_repeat_params(struct evdev_dev *evdev, uint16_t property, int value)
{
    if (evdev != NULL && property < REP_CNT)
        evdev->ev_rep[property] = value;
}

int
evdev_set_report_size(struct evdev_dev *evdev, size_t report_size)
{
    if (evdev == NULL || report_size == 0)
        return (EINVAL);
    evdev->ev_report_size = report_size;
    return (0);
}

void
evdev_set_flag(struct evdev_dev *evdev, uint16_t flag)
{
    if (evdev != NULL && flag < EVDEV_FLAG_CNT)
        evdev_bitmap_set(evdev->ev_flags, flag);
}

void
evdev_set_cdev_mode(struct evdev_dev *evdev, uid_t uid, gid_t gid, int mode)
{
    if (evdev == NULL)
        return;
    evdev->ev_cdev_uid = uid;
    evdev->ev_cdev_gid = gid;
    evdev->ev_cdev_mode = mode;
}

static void
evdev_update_state(struct evdev_dev *evdev, uint16_t type, uint16_t code,
    int32_t value)
{
    uint8_t *states = NULL;
    uint16_t count = 0;

    if (type == EV_KEY) {
        states = evdev->ev_key_states;
        count = KEY_CNT;
    } else if (type == EV_LED) {
        states = evdev->ev_led_states;
        count = LED_CNT;
    } else if (type == EV_SND) {
        states = evdev->ev_snd_states;
        count = SND_CNT;
    } else if (type == EV_SW) {
        states = evdev->ev_sw_states;
        count = SW_CNT;
    } else if (type == EV_ABS && code < ABS_CNT) {
        evdev->ev_absinfo[code].value = value;
        return;
    }
    if (states == NULL || code >= count || value == 2)
        return;
    if (value != 0)
        evdev_bitmap_set(states, code);
    else
        evdev_bitmap_clear(states, code);
}

void
evdev_send_event(struct evdev_dev *evdev, uint16_t type, uint16_t code,
    int32_t value)
{
    if (evdev == NULL || !evdev->ev_registered ||
        evdev->ev_event_index < 0)
        return;
    evdev_update_state(evdev, type, code, value);
    keyboard_emit_linux_input_event(evdev->ev_event_index, type, code, value);
#if defined(__x86_64__) || defined(BSD_BRIDGE_HOST_TEST)
    if (evdev->ev_pointer)
        evdev_update_mouse_compat(evdev, type, code, value);
#endif
    if (!evdev->ev_pointer && type == EV_KEY && !evdev_pointer_key(code))
        evdev_emit_console_key(code, value);
}

int
evdev_push_event(struct evdev_dev *evdev, uint16_t type, uint16_t code,
    int32_t value)
{
    int locked;

    if (evdev == NULL)
        return (EINVAL);
    if (!evdev->ev_registered)
        return (ENXIO);
    locked = evdev_lock_if_needed(evdev);
    evdev_send_event(evdev, type, code, value);
    evdev_unlock_if_needed(evdev, locked);
    return (0);
}

int
evdev_mt_id_to_slot(struct evdev_dev *evdev, int32_t tracking_id)
{
    int slot;

    if (evdev == NULL)
        return (-1);
    for (slot = 0; slot < MAX_MT_SLOTS; ++slot) {
        if ((evdev->ev_mt_active & (uint16_t)(1u << slot)) != 0 &&
            evdev->ev_mt_slots[slot].id == tracking_id)
            return (slot);
    }
    for (slot = 0; slot < MAX_MT_SLOTS; ++slot) {
        if ((evdev->ev_mt_active & (uint16_t)(1u << slot)) == 0 &&
            (evdev->ev_mt_frame & (uint16_t)(1u << slot)) == 0)
            return (slot);
    }
    return (-1);
}

int
evdev_mt_push_slot(struct evdev_dev *evdev, int slot,
    union evdev_mt_slot *data)
{
    int axis;
    int locked;

    if (evdev == NULL || slot < 0 || slot >= MAX_MT_SLOTS)
        return (EINVAL);
    locked = evdev_lock_if_needed(evdev);
    evdev_send_event(evdev, EV_ABS, ABS_MT_SLOT, slot);
    if (data == NULL) {
        if ((evdev->ev_mt_active & (uint16_t)(1u << slot)) != 0)
            evdev_send_event(evdev, EV_ABS, ABS_MT_TRACKING_ID, -1);
        evdev->ev_mt_active &= (uint16_t)~(1u << slot);
        evdev->ev_mt_slots[slot].id = -1;
    } else {
        if ((evdev->ev_mt_active & (uint16_t)(1u << slot)) == 0 ||
            evdev->ev_mt_slots[slot].id != data->id)
            evdev_send_event(evdev, EV_ABS, ABS_MT_TRACKING_ID, data->id);
        for (axis = 0; axis < MT_CNT; ++axis) {
            uint16_t code = (uint16_t)(ABS_MT_FIRST + axis);
            if (code == ABS_MT_TRACKING_ID)
                continue;
            if ((evdev->ev_mt_active & (uint16_t)(1u << slot)) == 0 ||
                evdev->ev_mt_slots[slot].val[axis] != data->val[axis])
                evdev_send_event(evdev, EV_ABS, code, data->val[axis]);
        }
        evdev->ev_mt_slots[slot] = *data;
        evdev->ev_mt_active |= (uint16_t)(1u << slot);
        evdev->ev_mt_frame |= (uint16_t)(1u << slot);
    }
    evdev->ev_mt_last_slot = slot;
    evdev_unlock_if_needed(evdev, locked);
    return (0);
}

void
evdev_mt_match_frame(struct evdev_dev *evdev, union evdev_mt_slot *points,
    int size)
{
    uint16_t used = 0;
    int point;

    if (evdev == NULL || points == NULL || size <= 0)
        return;
    if (size > MAX_MT_SLOTS)
        size = MAX_MT_SLOTS;
    for (point = 0; point < size; ++point) {
        int best_slot = -1;
        uint64_t best_distance = UINT64_MAX;
        for (int slot = 0; slot < MAX_MT_SLOTS; ++slot) {
            int64_t dx;
            int64_t dy;
            uint64_t distance;
            if ((evdev->ev_mt_active & (uint16_t)(1u << slot)) == 0 ||
                (used & (uint16_t)(1u << slot)) != 0)
                continue;
            dx = (int64_t)points[point].x -
                (int64_t)evdev->ev_mt_slots[slot].x;
            dy = (int64_t)points[point].y -
                (int64_t)evdev->ev_mt_slots[slot].y;
            distance = (uint64_t)(dx * dx + dy * dy);
            if (distance < best_distance) {
                best_distance = distance;
                best_slot = slot;
            }
        }
        if (best_slot >= 0) {
            points[point].id = evdev->ev_mt_slots[best_slot].id;
            used |= (uint16_t)(1u << best_slot);
        } else {
            points[point].id = -1;
        }
    }
}

int
evdev_mt_push_frame(struct evdev_dev *evdev, union evdev_mt_slot *points,
    int size)
{
    uint16_t prior;
    int point;

    if (evdev == NULL || size < 0 || size > MAX_MT_SLOTS ||
        (size != 0 && points == NULL))
        return (EINVAL);
    prior = evdev->ev_mt_active;
    evdev->ev_mt_frame = 0;
    for (point = 0; point < size; ++point) {
        int slot = points[point].id >= 0 ?
            evdev_mt_id_to_slot(evdev, points[point].id) : -1;
        if (slot < 0)
            slot = evdev_mt_id_to_slot(evdev, -1);
        if (slot >= 0) {
            if (points[point].id < 0)
                points[point].id = slot;
            (void)evdev_mt_push_slot(evdev, slot, &points[point]);
        }
    }
    for (int slot = 0; slot < MAX_MT_SLOTS; ++slot) {
        uint16_t mask = (uint16_t)(1u << slot);
        if ((prior & mask) != 0 && (evdev->ev_mt_frame & mask) == 0)
            (void)evdev_mt_push_slot(evdev, slot, NULL);
    }
    return (0);
}

union evdev_mt_slot *
evdev_mt_get_match_slots(struct evdev_dev *evdev)
{
    return (evdev != NULL ? evdev->ev_mt_match_slots : NULL);
}

void
evdev_mt_push_autorel(struct evdev_dev *evdev)
{
    uint16_t active;

    if (evdev == NULL)
        return;
    active = evdev->ev_mt_active;
    for (int slot = 0; slot < MAX_MT_SLOTS; ++slot) {
        uint16_t mask = (uint16_t)(1u << slot);
        if ((active & mask) != 0 && (evdev->ev_mt_frame & mask) == 0)
            (void)evdev_mt_push_slot(evdev, slot, NULL);
    }
}
