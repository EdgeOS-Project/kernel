/* SPDX-License-Identifier: MPL-2.0 */
/* Transactional ownership state for native PCI USB controllers. */

#include "drivers/usb_handoff.h"

#define USB_HANDOFF_EBUSY 16
#define USB_HANDOFF_EINVAL 22

typedef struct usb_handoff_controller {
    usb_handoff_location_t location;
    usb_handoff_controller_prepare_fn prepare;
    usb_handoff_controller_restore_fn restore;
    void *context;
    uint8_t present;
    uint8_t claimed;
} usb_handoff_controller_t;

static usb_handoff_location_t
    g_reservations[USB_HANDOFF_MAX_LOCATIONS];
static uint32_t g_reservation_count;
static usb_handoff_controller_t
    g_controllers[USB_HANDOFF_MAX_CONTROLLERS];
static uint32_t g_controller_count;

static int
usb_handoff_location_equal(const usb_handoff_location_t *left,
    const usb_handoff_location_t *right)
{
    return left != 0 && right != 0 &&
        left->domain == right->domain &&
        left->bus == right->bus &&
        left->slot == right->slot &&
        left->function == right->function;
}

static int
usb_handoff_location_in_list(const usb_handoff_location_t *location,
    const usb_handoff_location_t *locations, uint32_t count)
{
    for (uint32_t index = 0; index < count; ++index) {
        if (usb_handoff_location_equal(location, &locations[index]))
            return 1;
    }
    return 0;
}

static int
usb_handoff_reservations_equal(
    const usb_handoff_location_t *locations, uint32_t count)
{
    if (count != g_reservation_count)
        return 0;
    for (uint32_t index = 0; index < count; ++index) {
        if (!usb_handoff_location_in_list(
            &locations[index], g_reservations, g_reservation_count))
            return 0;
    }
    return 1;
}

int
usb_handoff_reserve_locations(
    const usb_handoff_location_t *locations, uint32_t count)
{
    uint32_t added = 0;

    if ((count != 0 && locations == 0) ||
        count > USB_HANDOFF_MAX_LOCATIONS)
        return USB_HANDOFF_EINVAL;
    if (g_reservation_count != 0)
        return usb_handoff_reservations_equal(locations, count) ?
            0 : USB_HANDOFF_EBUSY;
    for (uint32_t index = 0; index < count; ++index) {
        if (locations[index].slot >= 32u ||
            locations[index].function >= 8u)
            return USB_HANDOFF_EINVAL;
        if (usb_handoff_location_in_list(
            &locations[index], g_reservations, added))
            continue;
        g_reservations[added++] = locations[index];
    }
    g_reservation_count = added;
    return 0;
}

int
usb_handoff_location_reserved(
    const usb_handoff_location_t *location)
{
    return usb_handoff_location_in_list(
        location, g_reservations, g_reservation_count);
}

int
usb_handoff_controller_register(
    const usb_handoff_location_t *location,
    usb_handoff_controller_prepare_fn prepare,
    usb_handoff_controller_restore_fn restore, void *context)
{
    usb_handoff_controller_t *controller;

    if (location == 0 || prepare == 0 || restore == 0 ||
        context == 0 || location->slot >= 32u ||
        location->function >= 8u)
        return USB_HANDOFF_EINVAL;
    for (uint32_t index = 0; index < g_controller_count; ++index) {
        if (usb_handoff_location_equal(
            location, &g_controllers[index].location))
            return USB_HANDOFF_EBUSY;
    }
    if (g_controller_count >= USB_HANDOFF_MAX_CONTROLLERS)
        return USB_HANDOFF_EBUSY;
    controller = &g_controllers[g_controller_count++];
    *controller = (usb_handoff_controller_t){
        .location = *location,
        .prepare = prepare,
        .restore = restore,
        .context = context,
        .present = 1,
    };
    return 0;
}

int
usb_handoff_prepare_locations(
    const usb_handoff_location_t *locations, uint32_t count,
    usb_handoff_state_t *state)
{
    uint32_t prepared_mask = 0;
    int error;

    if (state == 0 || state->controller_mask != 0 ||
        (count != 0 && locations == 0) ||
        count > USB_HANDOFF_MAX_LOCATIONS)
        return USB_HANDOFF_EINVAL;
    for (uint32_t index = 0; index < g_controller_count; ++index) {
        usb_handoff_controller_t *controller = &g_controllers[index];
        uint32_t bit = 1u << index;

        if (!controller->present ||
            !usb_handoff_location_in_list(
                &controller->location, locations, count))
            continue;
        if (controller->claimed) {
            error = USB_HANDOFF_EBUSY;
            goto rollback;
        }
        error = controller->prepare(controller->context);
        if (error != 0)
            goto rollback;
        controller->claimed = 1;
        prepared_mask |= bit;
    }
    state->controller_mask = prepared_mask;
    return 0;

rollback:
    for (uint32_t index = g_controller_count; index > 0; --index) {
        usb_handoff_controller_t *controller =
            &g_controllers[index - 1u];
        uint32_t bit = 1u << (index - 1u);

        if ((prepared_mask & bit) == 0)
            continue;
        (void)controller->restore(controller->context);
        controller->claimed = 0;
    }
    return error;
}

int
usb_handoff_restore(usb_handoff_state_t *state)
{
    uint32_t remaining;
    int first_error = 0;

    if (state == 0)
        return USB_HANDOFF_EINVAL;
    remaining = state->controller_mask;
    for (uint32_t index = g_controller_count; index > 0; --index) {
        usb_handoff_controller_t *controller =
            &g_controllers[index - 1u];
        uint32_t bit = 1u << (index - 1u);
        int error;

        if ((remaining & bit) == 0)
            continue;
        error = controller->restore(controller->context);
        if (error != 0) {
            if (first_error == 0)
                first_error = error;
            continue;
        }
        controller->claimed = 0;
        remaining &= ~bit;
    }
    state->controller_mask = remaining;
    if (remaining == 0)
        g_reservation_count = 0;
    return first_error;
}

int
usb_handoff_release_reservations(void)
{
    int first_error = 0;

    for (uint32_t index = 0; index < g_controller_count; ++index) {
        usb_handoff_controller_t *controller = &g_controllers[index];
        int error;

        if (controller->claimed ||
            !usb_handoff_location_in_list(
                &controller->location, g_reservations,
                g_reservation_count))
            continue;
        error = controller->restore(controller->context);
        if (error != 0 && first_error == 0)
            first_error = error;
    }
    if (first_error == 0)
        g_reservation_count = 0;
    return first_error;
}
