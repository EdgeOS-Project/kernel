/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>

#include "kernel/wait_runtime.h"

static uint64_t last_arch_deadline;

void kernel_arch_wait_deadline_request(uint64_t deadline_us) {
    last_arch_deadline = deadline_us;
}

int main(void) {
    assert(!kernel_wait_deadline_claim(1000u));
    kernel_wait_deadline_request(500u);
    kernel_wait_deadline_request(700u);
    assert(last_arch_deadline == 700u);
    assert(!kernel_wait_deadline_claim(499u));
    assert(kernel_wait_deadline_claim(500u));
    assert(!kernel_wait_deadline_claim(1000u));

    kernel_wait_deadline_request(600u);
    kernel_wait_deadline_request(700u);
    assert(!kernel_wait_deadline_claim(599u));
    assert(kernel_wait_deadline_claim(600u));
    kernel_wait_deadline_request(700u);
    assert(kernel_wait_deadline_claim(700u));
    assert(!kernel_wait_deadline_claim(UINT64_MAX));
    return 0;
}
