/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD-compatible typed linker sets for imported driver subsystems. */

#ifndef _SYS_LINKER_SET_H_
#define _SYS_LINKER_SET_H_

#define BSD_LINKER_SET_CONCAT_INNER(left, right) left##right
#define BSD_LINKER_SET_CONCAT(left, right) \
    BSD_LINKER_SET_CONCAT_INNER(left, right)

#if defined(_WIN32) || defined(EDGEOS_BSD_COFF_TARGET)
#define BSD_LINKER_SET_ENTRY(set, symbol)                               \
    static void const * const                                           \
    BSD_LINKER_SET_CONCAT(                                              \
        BSD_LINKER_SET_CONCAT(bsd_set_##set##_, symbol), __LINE__)      \
    __attribute__((section("set_" #set "$m"), used)) = &(symbol)
#elif defined(__ELF__)
#define BSD_LINKER_SET_ENTRY(set, symbol)                               \
    static void const * const                                           \
    BSD_LINKER_SET_CONCAT(                                              \
        BSD_LINKER_SET_CONCAT(bsd_set_##set##_, symbol), __LINE__)      \
    __attribute__((section("set_" #set "$m"), used)) = &(symbol)
#else
#define BSD_LINKER_SET_ENTRY(set, symbol)                               \
    static void const * const                                           \
    BSD_LINKER_SET_CONCAT(                                              \
        BSD_LINKER_SET_CONCAT(bsd_set_##set##_, symbol), __LINE__)      \
    __attribute__((section("set_" #set), used)) = &(symbol)
#endif

#define TEXT_SET(set, symbol) BSD_LINKER_SET_ENTRY(set, symbol)
#define DATA_SET(set, symbol) BSD_LINKER_SET_ENTRY(set, symbol)
#define DATA_WSET(set, symbol) BSD_LINKER_SET_ENTRY(set, symbol)
#define BSS_SET(set, symbol) BSD_LINKER_SET_ENTRY(set, symbol)
#define ABS_SET(set, symbol) BSD_LINKER_SET_ENTRY(set, symbol)
#define SET_ENTRY(set, symbol) BSD_LINKER_SET_ENTRY(set, symbol)

#if defined(_WIN32) || defined(EDGEOS_BSD_COFF_TARGET)
/*
 * PE/COFF does not synthesize ELF-style __start/__stop section symbols.
 * Ordered $a/$m/$z subsections provide real boundaries, while selectany
 * coalesces declarations emitted by multiple imported FreeBSD objects.
 */
#define SET_DECLARE(set, pointer_type)                                  \
    pointer_type *__start_set_##set                                     \
        __attribute__((section("set_" #set "$a"), selectany)) = 0;      \
    pointer_type *__stop_set_##set                                      \
        __attribute__((section("set_" #set "$z"), selectany)) = 0
#define SET_BEGIN(set) (&__start_set_##set + 1)
#elif defined(__ELF__)
/*
 * EdgeOS collects all imported sets in one output section so an ELF linker
 * cannot synthesize per-input-section __start/__stop symbols.  Ordered COMDAT
 * sentinels retain FreeBSD's contiguous pointer-array ABI without requiring a
 * linker-script entry for every imported set.  COMDAT coalescing also makes
 * repeated SET_DECLARE uses in shared driver headers harmless.
 */
#define SET_DECLARE(set, pointer_type)                                  \
    __asm__(".pushsection set_" #set                                   \
            "$a,\"aG\",@progbits,__start_set_" #set ",comdat\n"        \
            ".balign 8\n"                                               \
            ".weak __start_set_" #set "\n"                             \
            ".type __start_set_" #set ",@object\n"                     \
            "__start_set_" #set ":\n"                                  \
            ".quad 0\n"                                                 \
            ".size __start_set_" #set ",8\n"                           \
            ".popsection\n"                                             \
            ".pushsection set_" #set                                   \
            "$z,\"aG\",@progbits,__stop_set_" #set ",comdat\n"         \
            ".balign 8\n"                                               \
            ".weak __stop_set_" #set "\n"                              \
            ".type __stop_set_" #set ",@object\n"                      \
            "__stop_set_" #set ":\n"                                   \
            ".quad 0\n"                                                 \
            ".size __stop_set_" #set ",8\n"                            \
            ".popsection\n");                                           \
    extern pointer_type *__start_set_##set;                             \
    extern pointer_type *__stop_set_##set
#define SET_BEGIN(set) (&__start_set_##set + 1)
#else
#define SET_DECLARE(set, pointer_type)                                  \
    extern pointer_type *__start_set_##set __attribute__((weak));       \
    extern pointer_type *__stop_set_##set __attribute__((weak))
#define SET_BEGIN(set) (&__start_set_##set)
#endif

#define SET_LIMIT(set) (&__stop_set_##set)
#define SET_FOREACH(iterator, set)                                      \
    for ((iterator) = SET_BEGIN(set); (iterator) < SET_LIMIT(set);      \
         (iterator)++)
#define SET_ITEM(set, index) (SET_BEGIN(set)[index])
#define SET_COUNT(set) (SET_LIMIT(set) - SET_BEGIN(set))

#endif
