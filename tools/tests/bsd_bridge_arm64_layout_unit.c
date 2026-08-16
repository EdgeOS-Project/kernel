/* SPDX-License-Identifier: MPL-2.0 */
/* Compile-time ABI checks for the ARM64 FreeBSD driver frontend. */

#if !defined(EDGEOS_BSD_ARM64)
#error "The ARM64 BSD bridge architecture marker is required"
#endif

#if defined(_WIN32)
#error "BSD driver sources must use the FreeBSD LP64 frontend"
#endif

_Static_assert(sizeof(void *) == 8, "ARM64 pointers must be 64-bit");
_Static_assert(sizeof(long) == 8, "FreeBSD ARM64 requires LP64");

union bsd_bridge_arm64_packed_bitfield {
    struct {
        unsigned short identifier:11;
        unsigned char fragment:5;
    };
    unsigned short value;
} __attribute__((packed));

_Static_assert(sizeof(union bsd_bridge_arm64_packed_bitfield) == 2,
    "FreeBSD ARM64 packed bitfields must use AAPCS layout");

int
bsd_bridge_arm64_layout_compile_check(void)
{
    return (int)sizeof(union bsd_bridge_arm64_packed_bitfield);
}
