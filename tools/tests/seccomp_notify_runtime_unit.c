/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS seccomp user-notification runtime test. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/anonymous_fd.h"
#include "kernel/credentials.h"
#include "kernel/process_runtime.h"
#include "kernel/seccomp.h"

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    if (!identity) return -1;
    memset(identity, 0, sizeof(*identity));
    identity->effective_capabilities = UINT64_MAX;
    return 0;
}

int kernel_current_no_new_privileges(void) { return 1; }
edge_seccomp_state_t *kernel_arch_current_seccomp_state(void) { return 0; }
int kernel_arch_seccomp_synchronize_thread_group(
    const edge_seccomp_state_t *previous,
    const edge_seccomp_state_t *installed, uint32_t flags) {
    (void)previous;
    (void)installed;
    (void)flags;
    return 0;
}

int kernel_anonymous_fd_install_descriptor(
    kernel_anonymous_fd_kind_t kind, int32_t object_id,
    uint32_t status_flags, uint32_t descriptor_flags) {
    (void)kind;
    (void)object_id;
    (void)status_flags;
    (void)descriptor_flags;
    return -1;
}

static int check(int condition, const char *label) {
    if (condition) return 0;
    fprintf(stderr, "seccomp-notify-unit: %s\n", label);
    return 1;
}

typedef struct {
    int32_t listener;
    uint32_t waits;
} wait_context_t;

static void answer_on_wait(void *opaque) {
    wait_context_t *context = (wait_context_t *)opaque;
    edge_seccomp_notification_t notification;
    edge_seccomp_notification_response_t response;

    ++context->waits;
    if (context->waits != 1u) return;
    if (edge_seccomp_listener_receive(
            context->listener, &notification) != 0)
        return;
    memset(&response, 0, sizeof(response));
    response.id = notification.id;
    response.value = 123;
    (void)edge_seccomp_listener_respond(context->listener, &response);
}

int main(void) {
    edge_seccomp_data_t data;
    edge_seccomp_notification_t notification;
    edge_seccomp_notification_response_t response;
    edge_seccomp_notification_result_t result;
    edge_seccomp_listener_state_t state;
    uint64_t first_id = 0;
    uint64_t canceled_id = 0;
    uint64_t waited_id = 0;
    wait_context_t wait_context;
    int listener;
    int canceled_listener;
    int failures = 0;

    memset(&data, 0, sizeof(data));
    data.nr = 39;
    data.arch = 0xc000003eu;
    data.instruction_pointer = 0x12345678u;
    data.args[0] = 7u;

    listener = edge_seccomp_listener_create();
    failures += check(listener > 0, "create listener");
    failures += check(edge_seccomp_notification_submit(
        listener, 4242, &data, &first_id) == 0 && first_id != 0,
        "submit notification");
    failures += check(edge_seccomp_listener_query(listener, &state) == 0 &&
                      state.queued == 1 && state.delivered == 0,
                      "queued poll state");
    failures += check(edge_seccomp_notification_result(
        first_id, &result) == 0, "pending result");
    failures += check(edge_seccomp_listener_receive(
        listener, &notification) == 0 &&
        notification.id == first_id && notification.pid == 4242 &&
        notification.data.nr == data.nr &&
        notification.data.args[0] == data.args[0],
        "receive notification");
    failures += check(edge_seccomp_listener_id_valid(
        listener, first_id) == 0, "delivered identifier");
    failures += check(edge_seccomp_listener_query(listener, &state) == 0 &&
                      state.queued == 0 && state.delivered == 1,
                      "delivered poll state");

    memset(&response, 0, sizeof(response));
    response.id = first_id;
    response.value = 91;
    response.flags = EDGE_SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    failures += check(edge_seccomp_listener_respond(
        listener, &response) < 0, "reject continue with value");
    response.value = 0;
    response.flags = 0;
    response.error = -13;
    failures += check(edge_seccomp_listener_respond(
        listener, &response) == 0, "send response");
    failures += check(edge_seccomp_listener_respond(
        listener, &response) < 0, "single response");
    failures += check(edge_seccomp_notification_result(
        first_id, &result) == 1 && result.error == -13 &&
        !result.continue_syscall, "consume response");
    failures += check(edge_seccomp_listener_id_valid(
        listener, first_id) < 0, "consumed identifier invalid");

    memset(&wait_context, 0, sizeof(wait_context));
    wait_context.listener = listener;
    failures += check(edge_seccomp_notification_wait(
        listener, 4243, &data, &waited_id, &result,
        answer_on_wait, &wait_context) == 1 &&
        result.value == 123 && !result.error &&
        waited_id == 0 && wait_context.waits == 1u,
        "shared blocking notification wait");

    canceled_listener = edge_seccomp_listener_create();
    failures += check(canceled_listener > 0, "create canceled listener");
    failures += check(edge_seccomp_notification_submit(
        canceled_listener, 99, &data, &canceled_id) == 0,
        "submit canceled notification");
    edge_seccomp_listener_release(canceled_listener);
    failures += check(edge_seccomp_notification_result(
        canceled_id, &result) == -38, "closed listener returns ENOSYS");

    edge_seccomp_listener_release(listener);
    if (failures) return 1;
    puts("seccomp-notify-unit: PASS");
    return 0;
}
