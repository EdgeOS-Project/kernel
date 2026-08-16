/* SPDX-License-Identifier: MPL-2.0 */

#include <sys/types.h>
#include <sys/stdint.h>
#include <machine/endian.h>
#include <machine/_limits.h>
#include <machine/param.h>
#include <machine/cpufunc.h>
#include <machine/cpu.h>
#include <machine/clock.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <sys/bus_dma.h>
#include <sys/libkern.h>
#include <sys/mbuf.h>
#include <contrib/zlib/zlib.h>

_Static_assert(sizeof(void *) == 8, "BSD bridge requires 64-bit pointers");
_Static_assert(sizeof(register_t) == 8, "register_t must be 64-bit");
_Static_assert(sizeof(vm_paddr_t) == 8, "vm_paddr_t must be 64-bit");
_Static_assert(sizeof(time_t) == 8, "time_t must be 64-bit");
_Static_assert(__LONG_BIT == sizeof(long) * 8,
    "long limit must match the compiler ABI");
_Static_assert(__SIZE_T_MAX == UINT64_MAX,
    "size_t limit must match the 64-bit target");
_Static_assert(PAGE_SIZE == 4096, "BSD bridge pages must be 4 KiB");
_Static_assert(STACKALIGNBYTES == 15, "stack alignment must be 16 bytes");
_Static_assert(INT64_MAX == INT64_C(0x7fffffffffffffff),
    "FreeBSD int64 maximum must be preserved");
_Static_assert(UINTPTR_MAX == UINT64_MAX,
    "FreeBSD uintptr maximum must be preserved");
_Static_assert(sizeof(z_stream) > sizeof(void *) * 4,
    "FreeBSD drivers must receive the complete zlib stream interface");
_Static_assert(ZLIB_VERNUM >= 0x1200,
    "FreeBSD drivers require the maintained zlib interface");
_Static_assert(EXT_PACKET == 6 && EXT_EXTREF == 255,
    "FreeBSD external mbuf storage type values must remain stable");

#if defined(__aarch64__)
_Static_assert(CACHE_LINE_SIZE == 128,
    "arm64 FreeBSD cache-line contract must be preserved");
#elif defined(__x86_64__)
_Static_assert(CACHE_LINE_SIZE == 64,
    "x86_64 FreeBSD cache-line contract must be preserved");
#endif

static int
test_endian_conversions(void)
{
    const uint16_t value16 = 0x1234U;
    const uint32_t value32 = 0x12345678U;
    const uint64_t value64 = 0x0123456789abcdefULL;

    if (le16toh(htole16(value16)) != value16)
        return 1;
    if (le32toh(htole32(value32)) != value32)
        return 2;
    if (le64toh(htole64(value64)) != value64)
        return 3;
    if (be16toh(htobe16(value16)) != value16)
        return 4;
    if (be32toh(htobe32(value32)) != value32)
        return 5;
    if (be64toh(htobe64(value64)) != value64)
        return 6;
    return 0;
}

static int
test_cpu_helpers(void)
{
    uint64_t value64 = 0;
    uint32_t value32 = 0;

    writeq(&value64, 0x0123456789abcdefULL);
    writel(&value32, 0x12345678U);
    if (readq(&value64) != 0x0123456789abcdefULL)
        return 7;
    if (readl(&value32) != 0x12345678U)
        return 8;
    if (ilog2(UINT64_C(1) << 37) != 37)
        return 9;
    cpu_spinwait();
    return 0;
}

int
main(void)
{
    int result;

    result = test_endian_conversions();
    if (result != 0)
        return result;
    return test_cpu_helpers();
}
