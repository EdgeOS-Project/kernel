/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared BSD bridge sbuf and sysctl runtimes. */

#include "compat/freebsd/sys/sbuf.h"
#include "compat/freebsd/sys/sysctl.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"

static uint16_t test_static_u16 = UINT16_C(0x1234);
SYSCTL_U16(_hw, OID_AUTO, edgeos_test_u16, CTLFLAG_RW,
    &test_static_u16, 0, "test static 16-bit value");
static unsigned long test_static_ulong = 1234UL;
SYSCTL_ULONG(_hw, OID_AUTO, edgeos_test_ulong, CTLFLAG_RW,
    &test_static_ulong, 0, "test static unsigned long value");
SYSCTL_CONST_STRING(_hw, OID_AUTO, edgeos_test_const_string, CTLFLAG_RD,
    "EdgeOS", "test constant string");

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U, (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static void
test_sbuf_fixed_and_dynamic(void)
{
    char storage[32];
    char section_storage[32];
    struct sbuf fixed;
    struct sbuf section;
    struct sbuf *dynamic;
    ssize_t outer_length;
    ssize_t inner_length;

    assert(sbuf_new(&fixed, storage, sizeof(storage), SBUF_FIXEDLEN) ==
        &fixed);
    assert(sbuf_cat(&fixed, "virtio") == 0);
    assert(sbuf_printf(&fixed, "-%u", 42U) == 0);
    assert(sbuf_finish(&fixed) == 0);
    assert(bsd_strcmp(sbuf_data(&fixed), "virtio-42") == 0);
    assert(sbuf_len(&fixed) == 9);
    sbuf_delete(&fixed);

    dynamic = sbuf_new_auto();
    assert(dynamic != 0);
    for (int index = 0; index < 100; ++index)
        assert(sbuf_printf(dynamic, "%02u", (unsigned int)index) == 0);
    assert(sbuf_len(dynamic) == 200);
    assert(sbuf_finish(dynamic) == 0);
    assert(sbuf_done(dynamic));
    assert(sbuf_data(dynamic)[199] == '9');
    sbuf_delete(dynamic);

    assert(sbuf_new(&section, section_storage, sizeof(section_storage),
        SBUF_FIXEDLEN) == &section);
    sbuf_start_section(&section, &outer_length);
    assert(outer_length == -1);
    assert(sbuf_cat(&section, "abc") == 0);
    sbuf_start_section(&section, &inner_length);
    assert(inner_length == 3);
    assert(sbuf_cat(&section, "de") == 0);
    assert(sbuf_end_section(&section, inner_length, 4, '_') == 4);
    assert(sbuf_end_section(&section, outer_length, 1, '_') == 7);
    assert(sbuf_finish(&section) == 0);
    assert(bsd_strcmp(sbuf_data(&section), "abcde__") == 0);
    sbuf_delete(&section);
}

struct test_request_buffer {
    char output[128];
    size_t output_length;
    uint8_t input[128];
    size_t input_length;
};

static int
test_request_output(struct sysctl_req *request, const void *data,
    size_t length)
{
    struct test_request_buffer *buffer = request->oldptr;

    assert(buffer->output_length + length <= sizeof(buffer->output));
    bsd_memcpy(buffer->output + buffer->output_length, data, length);
    buffer->output_length += length;
    return 0;
}

static int
test_request_input(struct sysctl_req *request, void *data, size_t length)
{
    struct test_request_buffer *buffer = (void *)request->newptr;

    assert(length == buffer->input_length);
    bsd_memcpy(data, buffer->input, length);
    return 0;
}

static void
test_sysctl_context_and_handler(void)
{
    struct sysctl_ctx_list context;
    struct sysctl_oid *node;
    struct sysctl_oid *value_oid;
    struct sysctl_oid *value64_oid;
    struct sysctl_oid *opaque_oid;
    struct test_request_buffer buffer = {
        .input_length = sizeof(int),
    };
    struct sysctl_req request = {
        .oldptr = &buffer,
        .oldfunc = test_request_output,
        .newptr = &buffer,
        .newlen = sizeof(buffer.input),
        .newfunc = test_request_input,
    };
    int value = 11;
    int input = 77;
    uint64_t value64 = UINT64_C(0x123456789abcdef0);
    uint64_t input64 = UINT64_C(0xfedcba9876543210);
    uint8_t opaque_value[] = {0x10, 0x20, 0x30, 0x40};

    bsd_memcpy(buffer.input, &input, sizeof(input));

    assert(sysctl_ctx_init(&context) == 0);
    assert(sysctl___kern.oid_parent == &sysctl__children);
    assert(bsd_strcmp(sysctl___kern.oid_name, "kern") == 0);
    assert(sysctl___debug_acpi.oid_parent ==
        &sysctl___debug.oid_children);
    assert(bsd_strcmp(sysctl___debug_acpi.oid_name, "acpi") == 0);
    assert((sysctl___hw_edgeos_test_ulong.oid_kind & CTLTYPE) ==
        CTLTYPE_ULONG);
    assert(sysctl___hw_edgeos_test_ulong.oid_handler ==
        sysctl_handle_long);
    node = sysctl_add_oid(&context, SYSCTL_CHILDREN(&sysctl___hw),
        OID_AUTO, "edgeos_test", CTLTYPE_NODE | CTLFLAG_RD |
        CTLFLAG_MPSAFE, 0, 0, 0, "N", "test node", 0);
    assert(node != 0);
    value_oid = sysctl_add_oid(&context, SYSCTL_CHILDREN(node),
        OID_AUTO, "value", CTLTYPE_INT | CTLFLAG_RW |
        CTLFLAG_MPSAFE, &value, 0, sysctl_handle_int,
        "I", "test value", 0);
    assert(value_oid != 0);
    assert(value_oid->oid_handler(value_oid, value_oid->oid_arg1,
        value_oid->oid_arg2, &request) == 0);
    assert(buffer.output_length == sizeof(int));
    assert(value == 77);
    {
        struct sysctl_oid key = {
            .oid_number = value_oid->oid_number,
        };

        sysctl_wlock();
        sysctl_unregister_oid(value_oid);
        assert(RB_FIND(sysctl_oid_list, value_oid->oid_parent, &key) == 0);
        sysctl_register_oid(value_oid);
        assert(RB_FIND(sysctl_oid_list, value_oid->oid_parent, &key) ==
            value_oid);
        sysctl_wunlock();
    }
    buffer.output_length = 0;
    buffer.input_length = sizeof(input64);
    request.newlen = sizeof(input64);
    bsd_memcpy(buffer.input, &input64, sizeof(input64));
    value64_oid = SYSCTL_ADD_U64(&context, SYSCTL_CHILDREN(node),
        OID_AUTO, "value64", CTLFLAG_RW, &value64, 0,
        "test 64-bit value");
    assert(value64_oid != 0);
    assert(value64_oid->oid_handler(value64_oid, value64_oid->oid_arg1,
        value64_oid->oid_arg2, &request) == 0);
    assert(buffer.output_length == sizeof(uint64_t));
    assert(value64 == input64);
    buffer.output_length = 0;
    request.newptr = 0;
    request.newlen = 0;
    opaque_oid = SYSCTL_ADD_OPAQUE(&context, SYSCTL_CHILDREN(node),
        OID_AUTO, "opaque", CTLFLAG_RD, opaque_value,
        sizeof(opaque_value), "A", "test opaque value");
    assert(opaque_oid != 0);
    assert((opaque_oid->oid_kind & CTLTYPE) == CTLTYPE_OPAQUE);
    assert(opaque_oid->oid_arg2 == (intmax_t)sizeof(opaque_value));
    assert(opaque_oid->oid_handler(opaque_oid, opaque_oid->oid_arg1,
        opaque_oid->oid_arg2, &request) == 0);
    assert(buffer.output_length == sizeof(opaque_value));
    assert(bsd_memcmp(buffer.output, opaque_value,
        sizeof(opaque_value)) == 0);
    assert(sysctl_ctx_free(&context) == 0);
}

static void
test_sysctl_extended_handlers(void)
{
    struct test_request_buffer buffer = {0};
    struct sysctl_req request = {
        .oldptr = &buffer,
        .oldfunc = test_request_output,
        .newfunc = test_request_input,
    };
    struct sysctl_oid writable_string = {
        .oid_kind = CTLTYPE_STRING | CTLFLAG_RW,
    };
    counter_u64_t counter;
    int8_t signed_byte = -12;
    uint8_t boolean = 1;
    int16_t signed_word = -1234;
    int32_t signed_dword = -12345678;
    long signed_long = -123456789L;
    uint16_t word = 0x1234;
    char text[8] = "old";
    char unterminated[3] = {'a', 'b', 'c'};
    uint8_t next_boolean = 0;
    int8_t next_signed_byte = 34;
    int16_t next_signed_word = 2345;
    int32_t next_signed_dword = 12345678;
    long next_signed_long = 123456789L;
    uint16_t next_word = 0xabcd;
    uint64_t counter_value = 0;
    int64_t milliseconds;
    int64_t next_milliseconds = 2750;
    int64_t interval = INT64_C(3) << 31;

    assert((sysctl___hw_edgeos_test_u16.oid_kind & CTLTYPE) ==
        CTLTYPE_U16);
    assert(sysctl___hw_edgeos_test_u16.oid_arg1 == &test_static_u16);
    assert(sysctl___hw_edgeos_test_u16.oid_handler == sysctl_handle_u16);
    assert((sysctl___hw_edgeos_test_const_string.oid_kind & CTLTYPE) ==
        CTLTYPE_STRING);
    assert((sysctl___hw_edgeos_test_const_string.oid_kind & CTLFLAG_WR) ==
        0);
    assert(bsd_strcmp(
        sysctl___hw_edgeos_test_const_string.oid_arg1, "EdgeOS") == 0);
    assert(sysctl___hw_edgeos_test_const_string.oid_handler ==
        sysctl_handle_string);

    assert(sysctl_handle_bool(0, &boolean, 0, &request) == 0);
    assert(buffer.output_length == sizeof(boolean));
    assert((uint8_t)buffer.output[0] == 1);

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, &next_boolean, sizeof(next_boolean));
    buffer.input_length = sizeof(next_boolean);
    request.newptr = &buffer;
    request.newlen = sizeof(next_boolean);
    assert(sysctl_handle_u8(0, &boolean, 0, &request) == 0);
    assert(boolean == 0);

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, &next_word, sizeof(next_word));
    buffer.input_length = sizeof(next_word);
    request.newlen = sizeof(next_word);
    assert(sysctl_handle_u16(0, &word, 0, &request) == 0);
    assert(word == 0xabcd);

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, &next_signed_byte, sizeof(next_signed_byte));
    buffer.input_length = sizeof(next_signed_byte);
    request.newlen = sizeof(next_signed_byte);
    assert(sysctl_handle_8(0, &signed_byte, 0, &request) == 0);
    assert(signed_byte == 34);

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, &next_signed_word, sizeof(next_signed_word));
    buffer.input_length = sizeof(next_signed_word);
    request.newlen = sizeof(next_signed_word);
    assert(sysctl_handle_16(0, &signed_word, 0, &request) == 0);
    assert(signed_word == 2345);

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, &next_signed_dword, sizeof(next_signed_dword));
    buffer.input_length = sizeof(next_signed_dword);
    request.newlen = sizeof(next_signed_dword);
    assert(sysctl_handle_32(0, &signed_dword, 0, &request) == 0);
    assert(signed_dword == 12345678);

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, &next_signed_long, sizeof(next_signed_long));
    buffer.input_length = sizeof(next_signed_long);
    request.newlen = sizeof(next_signed_long);
    assert(sysctl_handle_long(0, &signed_long, 0, &request) == 0);
    assert(signed_long == 123456789L);

    buffer.output_length = 0;
    request.newlen = sizeof(next_signed_dword);
    assert(sysctl_handle_32(0, 0, 7, &request) == EPERM);
    assert(buffer.output_length == sizeof(next_signed_dword));

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, "new", 3);
    buffer.input_length = 3;
    request.newlen = 3;
    assert(sysctl_handle_string(
        &writable_string, text, sizeof(text), &request) == 0);
    assert(bsd_strcmp(text, "new") == 0);

    buffer.output_length = 0;
    request.newptr = 0;
    request.newlen = 0;
    assert(sysctl_handle_string(
        0, unterminated, sizeof(unterminated), &request) == 0);
    assert(buffer.output_length == sizeof(unterminated));
    assert(bsd_memcmp(buffer.output, unterminated,
        sizeof(unterminated)) == 0);

    counter = counter_u64_alloc(M_NOWAIT);
    assert(counter != 0);
    counter_u64_add(counter, 42);
    buffer.output_length = 0;
    assert(sysctl_handle_counter_u64(
        0, &counter, 0, &request) == 0);
    assert(buffer.output_length == sizeof(uint64_t));
    bsd_memcpy(&counter_value, buffer.output, sizeof(counter_value));
    assert(counter_value == 42);
    counter_u64_free(counter);

    buffer.output_length = 0;
    bsd_memcpy(buffer.input, &next_milliseconds,
        sizeof(next_milliseconds));
    buffer.input_length = sizeof(next_milliseconds);
    request.newptr = &buffer;
    request.newlen = sizeof(next_milliseconds);
    assert(sysctl_msec_to_sbintime(0, &interval, 0, &request) == 0);
    assert(buffer.output_length == sizeof(milliseconds));
    bsd_memcpy(&milliseconds, buffer.output, sizeof(milliseconds));
    assert(milliseconds == 1500);
    buffer.output_length = 0;
    request.newptr = 0;
    request.newlen = 0;
    assert(sysctl_msec_to_sbintime(0, &interval, 0, &request) == 0);
    assert(buffer.output_length == sizeof(milliseconds));
    bsd_memcpy(&milliseconds, buffer.output, sizeof(milliseconds));
    assert(milliseconds == next_milliseconds);

    interval = -1;
    buffer.output_length = 0;
    assert(sysctl_msec_to_sbintime(0, &interval, 0, &request) == 0);
    bsd_memcpy(&milliseconds, buffer.output, sizeof(milliseconds));
    assert(milliseconds == -1);

    next_milliseconds = INT64_C(-2147483648000);
    bsd_memcpy(buffer.input, &next_milliseconds,
        sizeof(next_milliseconds));
    buffer.input_length = sizeof(next_milliseconds);
    request.newptr = &buffer;
    request.newlen = sizeof(next_milliseconds);
    buffer.output_length = 0;
    assert(sysctl_msec_to_sbintime(0, &interval, 0, &request) == 0);
    assert(interval == INT64_MIN);

    next_milliseconds = INT64_MAX;
    bsd_memcpy(buffer.input, &next_milliseconds,
        sizeof(next_milliseconds));
    buffer.input_length = sizeof(next_milliseconds);
    buffer.output_length = 0;
    assert(sysctl_msec_to_sbintime(0, &interval, 0, &request) == EINVAL);
    assert(interval == INT64_MIN);

    assert(sysctl_msec_to_sbintime(0, 0, 0, &request) == EINVAL);

    assert(sysctl_wire_old_buffer(&request, 64) == 0);
    assert(sysctl_wire_old_buffer(0, 64) == 22);
}

static void
test_sbuf_sysctl_drain(void)
{
    struct test_request_buffer buffer = {0};
    struct sysctl_req request = {
        .oldptr = &buffer,
        .oldfunc = test_request_output,
    };
    struct sbuf string;

    assert(sbuf_new_for_sysctl(&string, 0, 8, &request) == &string);
    assert(sbuf_cat(&string, "feature-list") == 0);
    assert(sbuf_finish(&string) == 0);
    assert(buffer.output_length == 12);
    assert(bsd_memcmp(buffer.output, "feature-list", 12) == 0);
    sbuf_delete(&string);
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };

    assert(bsd_allocator_initialize(&allocator) == 0);
    test_sbuf_fixed_and_dynamic();
    test_sysctl_context_and_handler();
    test_sysctl_extended_handlers();
    test_sbuf_sysctl_drain();
    assert(M_TEMP->bytes_allocated == M_TEMP->bytes_freed);
    return 0;
}
