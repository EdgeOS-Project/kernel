/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for transactional PCI USB controller ownership. */

#include "drivers/usb_handoff.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

typedef struct test_controller {
    int active;
    int reserved;
    int prepare_error;
    int restore_error;
    int prepare_count;
    int restore_count;
} test_controller_t;

static int
test_prepare(void *opaque_context)
{
    test_controller_t *context = opaque_context;

    context->prepare_count++;
    if (context->prepare_error)
        return context->prepare_error;
    if (context->active)
        return 16;
    context->reserved = 1;
    return 0;
}

static int
test_restore(void *opaque_context)
{
    test_controller_t *context = opaque_context;

    context->restore_count++;
    if (context->restore_error)
        return context->restore_error;
    context->reserved = 0;
    context->active = 1;
    return 0;
}

int
main(void)
{
    const usb_handoff_location_t first = {
        .domain = 0, .bus = 0, .slot = 5, .function = 0,
    };
    const usb_handoff_location_t second = {
        .domain = 0, .bus = 0, .slot = 6, .function = 0,
    };
    const usb_handoff_location_t unrelated = {
        .domain = 0, .bus = 0, .slot = 10, .function = 0,
    };
    usb_handoff_location_t selected[2] = { second, unrelated };
    usb_handoff_state_t state = {0};
    test_controller_t first_controller = {0};
    test_controller_t second_controller = {0};

    assert(usb_handoff_controller_register(
        &first, test_prepare, test_restore, &first_controller) == 0);
    assert(usb_handoff_controller_register(
        &second, test_prepare, test_restore, &second_controller) == 0);
    assert(usb_handoff_controller_register(
        &second, test_prepare, test_restore, &second_controller) == 16);

    assert(usb_handoff_reserve_locations(selected, 2) == 0);
    assert(usb_handoff_location_reserved(&first) == 0);
    assert(usb_handoff_location_reserved(&second) == 1);
    assert(usb_handoff_reserve_locations(selected, 2) == 0);
    assert(usb_handoff_prepare_locations(selected, 2, &state) == 0);
    assert(state.controller_mask == 2u);
    assert(second_controller.prepare_count == 1);
    assert(second_controller.reserved == 1);
    assert(usb_handoff_restore(&state) == 0);
    assert(state.controller_mask == 0);
    assert(second_controller.restore_count == 1);
    assert(second_controller.active == 1);
    assert(usb_handoff_location_reserved(&second) == 0);

    second_controller.active = 0;
    second_controller.prepare_error = 5;
    assert(usb_handoff_reserve_locations(&second, 1) == 0);
    assert(usb_handoff_prepare_locations(&second, 1, &state) == 5);
    assert(state.controller_mask == 0);
    second_controller.prepare_error = 0;
    assert(usb_handoff_release_reservations() == 0);
    assert(second_controller.restore_count == 2);
    assert(second_controller.active == 1);

    second_controller.active = 0;
    assert(usb_handoff_reserve_locations(&second, 1) == 0);
    second_controller.restore_error = 7;
    assert(usb_handoff_release_reservations() == 7);
    assert(usb_handoff_location_reserved(&second) == 1);
    second_controller.restore_error = 0;
    assert(usb_handoff_release_reservations() == 0);
    assert(usb_handoff_location_reserved(&second) == 0);

    first_controller.active = 1;
    assert(usb_handoff_reserve_locations(&first, 1) == 0);
    assert(usb_handoff_prepare_locations(&first, 1, &state) == 16);
    assert(state.controller_mask == 0);
    first_controller.active = 0;
    assert(usb_handoff_release_reservations() == 0);

    puts("usb_handoff_unit: PASS");
    return 0;
}
