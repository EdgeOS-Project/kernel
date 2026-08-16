/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD Driver Bridge core runtime helpers. */

#include <assert.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/systm.h"

static void
test_memory_and_strings(void)
{
    char buffer[16];
    char fields[] = "one,two,,four";
    char *field_cursor = fields;
    char *end;
    char overlap[] = "abcdef";
    const char *fdt_name = "virtio,mmio";
    const char *serial_name = "freebsd-usb-serial";

    bsd_memset(buffer, 0xa5, sizeof(buffer));
    assert((unsigned char)buffer[0] == 0xa5);
    bsd_memcpy(buffer, "edge", 5);
    assert(bsd_strcmp(buffer, "edge") == 0);
    assert(bsd_strncmp(buffer, "edgy", 3) == 0);
    assert(bsd_strncasecmp("Phy-Mode", "pHY-mode-extra", 8) == 0);
    assert(bsd_strncasecmp("rgmii", "RGMII", 6) == 0);
    assert(bsd_strncasecmp("rmii", "rgmii", 4) > 0);
    assert(bsd_memcmp(buffer, "edge", 5) == 0);
    assert(bsd_memchr(buffer, 'g', 5) == buffer + 2);
    assert(bsd_memchr(buffer, 'x', 5) == 0);
    assert(bsd_strnlen(buffer, 2) == 2);
    assert(bsd_strnlen(buffer, sizeof(buffer)) == 4);
    assert(bsd_strrchr(fdt_name, 'i') == fdt_name + 9);
    assert(bsd_strrchr(fdt_name, '\0') == fdt_name + 11);
    assert(bsd_strrchr(fdt_name, 'x') == 0);
    assert(bsd_strchr(fdt_name, ',') == fdt_name + 6);
    assert(bsd_strchr(fdt_name, '\0') == fdt_name + 11);

    bsd_memmove(overlap + 1, overlap, 5);
    assert(bsd_strcmp(overlap, "aabcde") == 0);

    assert(bsd_strlcpy(buffer, "driver-bridge", 7) == 13);
    assert(bsd_strcmp(buffer, "driver") == 0);
    assert(bsd_strlcat(buffer, "-x", sizeof(buffer)) == 8);
    assert(bsd_strcmp(buffer, "driver-x") == 0);
    buffer[0] = '\0';
    assert(bsd_strcat(buffer, "if") == buffer);
    assert(bsd_strcat(buffer, "lib") == buffer);
    assert(bsd_strcmp(buffer, "iflib") == 0);
    bsd_memset(buffer, 'x', sizeof(buffer));
    assert(bsd_strncpy(buffer, "usb", 6) == buffer);
    assert(bsd_memcmp(buffer, "usb\0\0\0", 6) == 0);
    assert(bsd_strstr(serial_name, "usb") == &serial_name[8]);
    assert(bsd_strstr(serial_name, "audio") == 0);
    assert(bsd_strstr(serial_name, "") == serial_name);
    assert(bsd_strcmp(bsd_strsep(&field_cursor, ","), "one") == 0);
    assert(bsd_strcmp(bsd_strsep(&field_cursor, ","), "two") == 0);
    assert(bsd_strcmp(bsd_strsep(&field_cursor, ","), "") == 0);
    assert(bsd_strcmp(bsd_strsep(&field_cursor, ","), "four") == 0);
    assert(bsd_strsep(&field_cursor, ",") == 0);

    assert(bsd_strtoul("  +075rest", &end, 0) == 61);
    assert(bsd_strcmp(end, "rest") == 0);
    assert(bsd_strtoul("-0x10tail", &end, 0) == ~0ul - 15ul);
    assert(bsd_strcmp(end, "tail") == 0);
    assert(bsd_strtoul("xyz", &end, 10) == 0);
    assert(end && *end == 'x');
    assert(bsd_strtoul("184467440737095516160", &end, 10) == ~0ul);
    assert(*end == '\0');

    bsd_memset(buffer, 0, sizeof(buffer));
    assert(bsd_copyin("copy", buffer, 5) == 0);
    assert(bsd_strcmp(buffer, "copy") == 0);
    assert(bsd_copyout("out", buffer, 4) == 0);
    assert(bsd_strcmp(buffer, "out") == 0);
    assert(bsd_copyin(0, buffer, 1) == 14);
}

static void
test_formatting(void)
{
    char buffer[128];
    char small[6];
    unsigned char bytes[] = { 0x01, 0xab, 0xff };

    assert(bsd_snprintf(buffer, sizeof(buffer), "%s-%d-%08x-%llu",
        "virtio", -7, 0x12U, 123456789ULL) == 28);
    assert(bsd_strcmp(buffer, "virtio--7-00000012-123456789") == 0);

    assert(bsd_snprintf(small, sizeof(small), "abcdefghi") == 9);
    assert(bsd_strcmp(small, "abcde") == 0);
    assert(bsd_snprintf(0, 0, "%s:%d", "vq", 12) == 5);
    assert(bsd_snprintf(buffer, sizeof(buffer), "%04d", -7) == 4);
    assert(bsd_strcmp(buffer, "-007") == 0);
    assert(bsd_snprintf(buffer, sizeof(buffer),
        "%#jx %#08X %hhu %hu %zu %td",
        UINTMAX_C(0x1234), 0xabU, 258U, 65538U,
        (size_t)42, (ptrdiff_t)-5) == 25);
    assert(bsd_strcmp(buffer,
        "0x1234 0X0000AB 2 2 42 -5") == 0);
    assert(bsd_snprintf(buffer, sizeof(buffer), "[%*.*s][%-4c]",
        6, 3, "virtio", 'x') == 14);
    assert(bsd_strcmp(buffer, "[   vir][x   ]") == 0);
    assert(bsd_snprintf(buffer, sizeof(buffer), "%b", 5U,
        "\20\1READY\3FEATURE") == 16);
    assert(bsd_strcmp(buffer, "5<READY,FEATURE>") == 0);
    assert(bsd_snprintf(buffer, sizeof(buffer), "%-14b", 3U,
        "\20\200BIT1\201BIT2") == 14);
    assert(bsd_strcmp(buffer, "3<BIT1,BIT2>  ") == 0);
    assert(bsd_snprintf(buffer, sizeof(buffer), "%3D", bytes, ":") == 8);
    assert(bsd_strcmp(buffer, "01:AB:FF") == 0);
    assert(bsd_sprintf(buffer, "%s-%u", "iflib", 7u) == 7);
    assert(bsd_strcmp(buffer, "iflib-7") == 0);
}

static void
test_quad_conversions(void)
{
    char *end;

    assert(bsd_strtouq("18446744073709551615tail", &end, 10) ==
        UINT64_MAX);
    assert(bsd_strcmp(end, "tail") == 0);
    assert(bsd_strtouq("18446744073709551616", &end, 10) ==
        UINT64_MAX);
    assert(*end == '\0');
    assert(bsd_strtouq("-1", &end, 10) == UINT64_MAX);
    assert(*end == '\0');
    assert(bsd_strtouq("0xfeed-stop", &end, 0) == UINT64_C(0xfeed));
    assert(bsd_strcmp(end, "-stop") == 0);

    assert(bsd_strtoq("9223372036854775807tail", &end, 10) ==
        INT64_MAX);
    assert(bsd_strcmp(end, "tail") == 0);
    assert(bsd_strtoq("9223372036854775808", &end, 10) ==
        INT64_MAX);
    assert(*end == '\0');
    assert(bsd_strtoq("-9223372036854775808", &end, 10) ==
        INT64_MIN);
    assert(*end == '\0');
    assert(bsd_strtoq("-9223372036854775809", &end, 10) ==
        INT64_MIN);
    assert(*end == '\0');
    assert(bsd_strtoq("not-a-number", &end, 10) == 0);
    assert(end && *end == 'n');
}

static void
test_bit_helpers(void)
{
    assert(bsd_ffs(0) == 0);
    assert(bsd_ffs(8) == 4);
    assert(bsd_ffsll(0) == 0);
    assert(bsd_ffsll(1LL << 50) == 51);
    assert(bsd_fls(8) == 4);
    assert(bsd_ffsl(1L << 40) == 41);
    assert(bsd_flsl(1L << 40) == 41);
    assert(bsd_flsll(1LL << 50) == 51);
    assert(bsd_roundup_power_of_two(0) == 1);
    assert(bsd_roundup_power_of_two(1) == 1);
    assert(bsd_roundup_power_of_two(9) == 16);
    assert(bsd_roundup_power_of_two(UINT64_C(1) << 63) ==
        (UINT64_C(1) << 63));
    assert(bsd_roundup_power_of_two((UINT64_C(1) << 63) + 1) == 0);
    assert(bsd_rounddown_power_of_two(0) == 0);
    assert(bsd_rounddown_power_of_two(1) == 1);
    assert(bsd_rounddown_power_of_two(9) == 8);
    assert(bsd_rounddown_power_of_two(UINT64_MAX) ==
        (UINT64_C(1) << 63));
    bsd_critical_enter();
    bsd_critical_enter();
    bsd_critical_exit();
    bsd_critical_exit();
    bsd_critical_exit();
}

static void
test_unit_number_allocator(void)
{
    struct unrhdr local;
    struct unrhdr *dynamic = new_unrhdr(7, 9, 0);

    assert(dynamic != 0);
    assert(alloc_unr(dynamic) == 7);
    assert(alloc_unr(dynamic) == 8);
    assert(alloc_unr_specific(dynamic, 9) == 9);
    assert(alloc_unr(dynamic) == -1);
    assert(alloc_unr_specific(dynamic, 8) == -1);
    free_unr(dynamic, 8);
    assert(alloc_unrl(dynamic) == 8);
    clear_unrhdr(dynamic);
    assert(alloc_unr(dynamic) == 7);
    delete_unrhdr(dynamic);

    init_unrhdr(&local, 3, 3, 0);
    assert(alloc_unr(&local) == 3);
    assert(alloc_unr(&local) == -1);
    clean_unrhdr(&local);
    assert(alloc_unr(&local) == 3);
    clean_unrhdrl(&local);
}

int
main(void)
{
    test_memory_and_strings();
    test_formatting();
    test_quad_conversions();
    test_bit_helpers();
    test_unit_number_allocator();
    return 0;
}
