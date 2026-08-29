/* SPDX-License-Identifier: MPL-2.0 */

#include <stdio.h>
#include <pthread.h>

#include "kernel/deferred_work.h"

static uint32_t input_kicks;

void kernel_arch_input_work_request(void) {
    ++input_kicks;
}

static int failures;

static void *request_from_cpu(void *argument) {
    (void)argument;
    for (unsigned int iteration = 0; iteration < 10000u; ++iteration) {
        kernel_deferred_work_request();
        kernel_display_work_request();
    }
    return 0;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
}

int main(void) {
    expect_true("initially idle", !kernel_deferred_work_pending());

    kernel_input_work_request();
    kernel_input_work_request();
    expect_true("input requests coalesce", kernel_input_work_pending());
    expect_true("input transition kicks once", input_kicks == 1u);
    expect_true("input take observes request", kernel_input_work_take());
    kernel_input_work_request();
    expect_true("input rearm kicks again", input_kicks == 2u);
    expect_true("input rearm take", kernel_input_work_take());
    kernel_deferred_work_request();
    kernel_deferred_work_request();
    expect_true("requests coalesce", kernel_deferred_work_pending());
    expect_true("take observes request", kernel_deferred_work_take());
    expect_true("take clears request", !kernel_deferred_work_take());

    expect_true("first cadence tick is early",
                !kernel_deferred_work_tick(3u));
    expect_true("second cadence tick is early",
                !kernel_deferred_work_tick(3u));
    expect_true("third cadence tick is due",
                kernel_deferred_work_tick(3u));
    expect_true("cadence publishes request",
                kernel_deferred_work_take());
    expect_true("cadence restarts after take",
                !kernel_deferred_work_tick(3u));

    expect_true("zero interval fires immediately",
                kernel_deferred_work_tick(0u));
    expect_true("immediate cadence is consumable",
                kernel_deferred_work_take());

    expect_true("display work initially idle",
                !kernel_display_work_pending());
    kernel_display_work_request();
    kernel_display_work_request();
    expect_true("display requests coalesce",
                kernel_display_work_pending());
    expect_true("display request is consumable",
                kernel_display_work_take());
    expect_true("display take clears request",
                !kernel_display_work_take());

    kernel_display_deadline_request(200u);
    kernel_display_deadline_request(300u);
    expect_true("later display deadline does not replace earlier one",
                kernel_display_deadline() == 200u);
    expect_true("display deadline remains idle before expiry",
                !kernel_display_deadline_poll(199u));
    expect_true("display deadline remains armed before expiry",
                kernel_display_deadline() == 200u);
    expect_true("display deadline publishes work at expiry",
                kernel_display_deadline_poll(200u));
    expect_true("expired display deadline is cleared",
                kernel_display_deadline() == 0u);
    expect_true("expired display deadline work is consumable",
                kernel_display_work_take());
    expect_true("expired display deadline fires once",
                !kernel_display_deadline_poll(300u));

    kernel_display_deadline_request(500u);
    kernel_display_deadline_request(400u);
    expect_true("earlier display deadline replaces later one",
                kernel_display_deadline() == 400u);
    expect_true("replaced display deadline publishes at earlier expiry",
                kernel_display_deadline_poll(400u));
    expect_true("replaced display deadline work is consumable",
                kernel_display_work_take());

    expect_true("input work initially idle",
                !kernel_input_work_pending());
    kernel_input_work_request();
    kernel_input_work_request();
    expect_true("input requests coalesce",
                kernel_input_work_pending());
    expect_true("input request is consumable",
                kernel_input_work_take());
    expect_true("input take clears request",
                !kernel_input_work_take());

    kernel_deferred_work_request();
    kernel_display_work_request();
    expect_true("bootstrap CPU services shared work",
                kernel_deferred_work_service_pending(0u));
    expect_true("secondary CPU services display work",
                kernel_deferred_work_service_pending(1u));
    expect_true("service selection does not consume general work",
                kernel_deferred_work_pending());
    expect_true("service selection does not consume display work",
                kernel_display_work_pending());
    {
        uint32_t ready = kernel_deferred_work_take_ready();
        expect_true("combined take includes display",
                    (ready & KERNEL_DEFERRED_WORK_DISPLAY) != 0u);
        expect_true("combined take includes general",
                    (ready & KERNEL_DEFERRED_WORK_GENERAL) != 0u);
        expect_true("combined take clears general",
                    !kernel_deferred_work_pending());
        expect_true("combined take clears display",
                    !kernel_display_work_pending());
    }

    kernel_deferred_work_request();
    expect_true("take consumes first general request",
                kernel_deferred_work_take_ready() ==
                    KERNEL_DEFERRED_WORK_GENERAL);
    kernel_display_work_request();
    expect_true("request during service remains pending",
                kernel_display_work_pending());
    expect_true("next take observes requeued display",
                kernel_deferred_work_take_ready() ==
                    KERNEL_DEFERRED_WORK_DISPLAY);

    kernel_deferred_work_request();
    kernel_input_work_request();
    expect_true("secondary CPU services input work",
                kernel_deferred_work_service_pending(1u));
    expect_true("combined take includes input and general",
                kernel_deferred_work_take_ready() ==
                    (KERNEL_DEFERRED_WORK_INPUT |
                     KERNEL_DEFERRED_WORK_GENERAL));

    {
        pthread_t workers[4];
        int created = 0;

        for (unsigned int index = 0; index < 4u; ++index) {
            if (pthread_create(&workers[index], 0,
                               request_from_cpu, 0) != 0)
                break;
            ++created;
        }
        expect_true("concurrent request workers created", created == 4);
        for (int index = 0; index < created; ++index)
            expect_true("concurrent request worker completed",
                        pthread_join(workers[index], 0) == 0);
        expect_true("concurrent requests preserve both classes",
                    kernel_deferred_work_take_ready() ==
                        (KERNEL_DEFERRED_WORK_DISPLAY |
                         KERNEL_DEFERRED_WORK_GENERAL));
    }

    if (failures) return 1;
    puts("deferred_work_unit: PASS");
    return 0;
}
