/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "kernel/linux_abi.h"

#define EFAULT 14
#define ENOTSUPP 524
#define RSEQ_SIGNATURE 0x53053053u

typedef struct test_memory {
    uint64_t base;
    uint8_t bytes[128];
} test_memory_t;

static int copy_from_test(void *context, void *destination,
                          uint64_t source, uint64_t size) {
    test_memory_t *memory = context;
    if (!memory || source < memory->base ||
        size > sizeof(memory->bytes) ||
        source - memory->base > sizeof(memory->bytes) - size)
        return -1;
    memcpy(destination, memory->bytes + source - memory->base, size);
    return 0;
}

static int copy_to_test(void *context, uint64_t destination,
                        const void *source, uint64_t size) {
    test_memory_t *memory = context;
    if (!memory || destination < memory->base ||
        size > sizeof(memory->bytes) ||
        destination - memory->base > sizeof(memory->bytes) - size)
        return -1;
    memcpy(memory->bytes + destination - memory->base, source, size);
    return 0;
}

static uint32_t read_u32(const test_memory_t *memory, uint32_t offset) {
    uint32_t value;
    memcpy(&value, memory->bytes + offset, sizeof(value));
    return value;
}

static void write_u32(test_memory_t *memory, uint32_t offset,
                      uint32_t value) {
    memcpy(memory->bytes + offset, &value, sizeof(value));
}

int main(void) {
    struct edge_linux_rseq_state state;
    test_memory_t memory;
    int force_reschedule;

    memset(&memory, 0, sizeof(memory));
    memory.base = 0x1000u;
    edge_linux_rseq_state_reset(&state);

    assert(edge_linux_rseq_register(
               &state, memory.base, EDGE_LINUX_RSEQ_LEGACY_SIZE,
               EDGE_LINUX_RSEQ_FLAG_SLICE_EXT_DEFAULT_ON,
               RSEQ_SIGNATURE, 2u, 0u, 7u,
               copy_to_test, &memory) == 0);
    assert(state.version == 1u && state.slice_enabled == 0u);
    assert(read_u32(&memory, 16u) == 0u);
    assert(edge_linux_rseq_slice_prctl(
               &state, EDGE_LINUX_PR_RSEQ_SLICE_EXTENSION_SET,
               EDGE_LINUX_PR_RSEQ_SLICE_EXT_ENABLE,
               copy_from_test, copy_to_test, &memory) == -ENOTSUPP);
    assert(edge_linux_rseq_register(
               &state, memory.base, EDGE_LINUX_RSEQ_LEGACY_SIZE,
               EDGE_LINUX_RSEQ_FLAG_UNREGISTER, RSEQ_SIGNATURE,
               2u, 0u, 7u, copy_to_test, &memory) == 0);

    memset(memory.bytes, 0, sizeof(memory.bytes));
    assert(edge_linux_rseq_register(
               &state, memory.base, EDGE_LINUX_RSEQ_FEATURE_SIZE,
               EDGE_LINUX_RSEQ_FLAG_SLICE_EXT_DEFAULT_ON,
               RSEQ_SIGNATURE, 3u, 1u, 8u,
               copy_to_test, &memory) == 0);
    assert(state.version == 2u && state.slice_enabled == 1u);
    assert(read_u32(&memory, 16u) ==
           (EDGE_LINUX_RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE |
            EDGE_LINUX_RSEQ_CS_FLAG_SLICE_EXT_ENABLED));

    write_u32(&memory, 28u, 1u);
    assert(edge_linux_rseq_slice_interrupt(
               &state, 100u, copy_from_test, copy_to_test, &memory) == 1);
    assert(state.slice_granted == 1u && state.slice_expires_us == 105u);
    assert(read_u32(&memory, 28u) == 0x100u);
    assert(edge_linux_rseq_slice_syscall_enter(
               &state, 1, &force_reschedule,
               copy_from_test, copy_to_test, &memory) == 0);
    assert(force_reschedule == 1 && read_u32(&memory, 28u) == 0u);
    assert(edge_linux_rseq_slice_yield(&state) == 1);
    assert(edge_linux_rseq_slice_yield(&state) == 0);

    write_u32(&memory, 28u, 1u);
    assert(edge_linux_rseq_slice_interrupt(
               &state, 200u, copy_from_test, copy_to_test, &memory) == 1);
    assert(edge_linux_rseq_slice_interrupt(
               &state, 205u, copy_from_test, copy_to_test, &memory) == 0);
    assert(state.slice_granted == 0u && read_u32(&memory, 28u) == 0u);

    assert(edge_linux_rseq_slice_prctl(
               &state, EDGE_LINUX_PR_RSEQ_SLICE_EXTENSION_SET, 0u,
               copy_from_test, copy_to_test, &memory) == 0);
    write_u32(&memory, 16u, 0u);
    assert(edge_linux_rseq_slice_prctl(
               &state, EDGE_LINUX_PR_RSEQ_SLICE_EXTENSION_SET,
               EDGE_LINUX_PR_RSEQ_SLICE_EXT_ENABLE,
               copy_from_test, copy_to_test, &memory) == -EFAULT);

    return 0;
}
