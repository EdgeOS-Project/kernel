/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise the actual syscall adapter with each supported architecture tag. */
#include <assert.h>
#include <string.h>
#define STRING_H
extern int puts(const char *text);
#define EDGEOS_HOST_TEST 1
#include "../../src/kernel/linux_syscall.c"

static char user_bytes[512];
static unsigned callback_count;
static int copy_string_bytes(void *context, void *destination,
                             uint64_t source, uint64_t length) {
    assert(context == user_bytes);
    assert(source >= 0x4000 && source - 0x4000 + length <= sizeof(user_bytes));
    assert(length <= 128 && length <= 4096 - (source & 4095));
    ++callback_count;
    memcpy(destination, user_bytes + (source - 0x4000), (size_t)length);
    return 0;
}
int main(void) {
    edge_linux_syscall_arch_ops_t ops = {.copy_from_user = copy_string_bytes};
    edge_linux_syscall_context_t context = {
        .arch_ops = &ops, .current_task = user_bytes
    };
    char output[512];
    memset(user_bytes, 'a', sizeof(user_bytes));
    user_bytes[255] = 0;
    for (unsigned arch = EDGE_LINUX_ARCH_X86_64; arch <= EDGE_LINUX_ARCH_IA32; ++arch) {
        context.architecture = (edge_linux_syscall_architecture_t)arch;
        callback_count = 0;
        memset(output, '#', sizeof(output));
        assert(edge_linux_copy_user_string(&context, 0x4000, output,
            sizeof(output), EDGE_LINUX_ENAMETOOLONG) == 255);
        assert(callback_count == 2 && output[256] == '#');
    }
    assert(edge_linux_copy_user_string(0, 0x4000, output, sizeof(output),
        EDGE_LINUX_ENAMETOOLONG) == -EDGE_LINUX_EFAULT);
    ops.copy_from_user = 0;
    assert(edge_linux_copy_user_string(&context, 0x4000, output, sizeof(output),
        EDGE_LINUX_ENAMETOOLONG) == -EDGE_LINUX_EFAULT);
    puts("user_string_syscall_unit: PASS");
    return 0;
}
