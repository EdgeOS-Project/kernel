/* SPDX-License-Identifier: MPL-2.0 */
/* Core runtime helpers for the EdgeOS FreeBSD driver bridge. */

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef BSD_BRIDGE_HOST_TEST
#include <stdio.h>
#include <stdlib.h>
#else
#include "kernel/system_runtime.h"
void printf(const char *format, ...);
#endif

#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/reboot.h"
#include "compat/freebsd/sys/_callout.h"
#include "compat/freebsd/sys/cpuset.h"
#include "compat/freebsd/sys/domainset.h"

struct malloc_type;

#ifndef EDGEOS_KERNEL_RELEASE
#define EDGEOS_KERNEL_RELEASE "2.0.8"
#endif

typedef struct {
    char *destination;
    size_t capacity;
    size_t length;
} bsd_format_output_t;

int hz = 1000;
const int osreldate = 200008;
const char osrelease[] = EDGEOS_KERNEL_RELEASE;
const char ostype[] = "EdgeOS";
const char kern_ident[] = "EDGEOS";
int tick = 1000;
volatile int ticks;
volatile long ticksl;
int bootverbose;
int cold;
int kdb_active;
int rebooting;
int dumping;
int mp_ncpus = 1;
int mp_ncores = 1;
int mp_maxid = 0;
int smp_threads_per_core = 1;
int smp_started = 1;
int vm_guest;

#define BSD_SYSTM_ENODEV 19

int
sysbeep(int frequency, sbintime_t duration)
{
    (void)frequency;
    (void)duration;
    return BSD_SYSTM_ENODEV;
}

cpuset_t all_cpus = { .__bits = { 1ul } };
cpuset_t cpuset_domain[1] = { { .__bits = { 1ul } } };
cpuset_t hlt_cpus_mask = { .__bits = { 0ul } };
struct domainset domainset_prefer[1] = {
    { .preferred_domain = 0 },
};
struct domainset domainset_round_robin[1] = {
    { .preferred_domain = 0 },
};
unsigned long maxphys = 1024UL * 1024UL;
unsigned long physmem = 1;
long Maxmem = 1;
long realmem = 1;

void
shutdown_nice(int howto)
{
    rebooting = 1;
#ifndef BSD_BRIDGE_HOST_TEST
    if ((howto & BSD_RB_POWEROFF) != 0)
        (void)kernel_system_power_action(KERNEL_POWER_OFF);
    else if ((howto & BSD_RB_HALT) != 0)
        (void)kernel_system_power_action(KERNEL_POWER_HALT);
    else
        (void)kernel_system_power_action(KERNEL_POWER_RESTART);
#else
    (void)howto;
#endif
}

#define BSD_CRITICAL_CPU_SLOTS 256u
#define BSD_UNR_HEADER_SLOTS 64u
#define BSD_UNR_ENTRY_SLOTS 2048u

typedef struct {
    uint64_t interrupt_state;
    uint32_t depth;
} bsd_critical_cpu_state_t;

typedef struct bsd_unr_entry {
    struct bsd_unr_entry *next;
    unsigned int item;
    uint8_t used;
} bsd_unr_entry_t;

static struct unrhdr g_unr_headers[BSD_UNR_HEADER_SLOTS];
static uint8_t g_unr_header_used[BSD_UNR_HEADER_SLOTS];
static bsd_unr_entry_t g_unr_entries[BSD_UNR_ENTRY_SLOTS];
static volatile uint8_t g_unr_guard;

#ifdef BSD_BRIDGE_HOST_TEST
static _Thread_local bsd_critical_cpu_state_t g_host_critical_state;
#else
static bsd_critical_cpu_state_t
    g_critical_cpu_state[BSD_CRITICAL_CPU_SLOTS];
#endif

__attribute__((weak))
void
bsd_kthread_critical_enter(void)
{
}

__attribute__((weak))
void
bsd_kthread_critical_exit(void)
{
}

static uint64_t
critical_interrupt_save_disable(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return 0;
#elif defined(__x86_64__)
    uint64_t state;

    __asm__ __volatile__(
        "pushfq; popq %0; cli" : "=r"(state) :: "memory");
    return state;
#elif defined(__aarch64__) || defined(_M_ARM64)
    uint64_t state;

    __asm__ __volatile__(
        "mrs %0, daif; msr daifset, #0xf"
        : "=r"(state) :: "memory");
    return state;
#else
#error "BSD Driver Bridge critical sections need an interrupt backend"
#endif
}

static void
critical_interrupt_restore(uint64_t state)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)state;
#elif defined(__x86_64__)
    if ((state & (UINT64_C(1) << 9)) != 0)
        __asm__ __volatile__("sti" ::: "memory");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("msr daif, %0" :: "r"(state) : "memory");
#endif
}

#ifndef BSD_BRIDGE_HOST_TEST
static unsigned int
critical_cpu_slot(void)
{
#if defined(__x86_64__)
    uint32_t eax = 1;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    __asm__ __volatile__(
        "cpuid"
        : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    (void)ecx;
    (void)edx;
    return (ebx >> 24) % BSD_CRITICAL_CPU_SLOTS;
#elif defined(__aarch64__) || defined(_M_ARM64)
    uint64_t mpidr;

    __asm__ __volatile__("mrs %0, mpidr_el1" : "=r"(mpidr));
    return ((unsigned int)(mpidr & UINT64_C(0xff)) ^
        (unsigned int)((mpidr >> 8) & UINT64_C(0xff)) ^
        (unsigned int)((mpidr >> 16) & UINT64_C(0xff)) ^
        (unsigned int)((mpidr >> 32) & UINT64_C(0xff))) %
        BSD_CRITICAL_CPU_SLOTS;
#endif
}
#endif

static bsd_critical_cpu_state_t *
critical_cpu_state(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return &g_host_critical_state;
#else
    return &g_critical_cpu_state[critical_cpu_slot()];
#endif
}

void
bsd_critical_enter(void)
{
    uint64_t interrupt_state = critical_interrupt_save_disable();
    bsd_critical_cpu_state_t *state = critical_cpu_state();

    if (state->depth++ == 0)
        state->interrupt_state = interrupt_state;
    bsd_kthread_critical_enter();
}

void
bsd_critical_exit(void)
{
    uint64_t interrupt_state = critical_interrupt_save_disable();
    bsd_critical_cpu_state_t *state = critical_cpu_state();

    if (state->depth == 0) {
        critical_interrupt_restore(interrupt_state);
        return;
    }
    bsd_kthread_critical_exit();
    if (--state->depth == 0)
        critical_interrupt_restore(state->interrupt_state);
}

static void
unr_lock(void)
{
    while (__atomic_test_and_set(&g_unr_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
unr_unlock(void)
{
    __atomic_clear(&g_unr_guard, __ATOMIC_RELEASE);
}

static void
unr_clear_locked(struct unrhdr *header)
{
    bsd_unr_entry_t *entry;

    if (!header)
        return;
    entry = header->entries;
    header->entries = 0;
    while (entry) {
        bsd_unr_entry_t *next = entry->next;

        entry->next = 0;
        entry->item = 0;
        entry->used = 0;
        entry = next;
    }
}

void
init_unrhdr(struct unrhdr *header, int low, int high, struct mtx *mutex)
{
    if (!header)
        return;
    header->low = low;
    header->high = high;
    header->entries = 0;
    header->mutex = mutex;
    header->bridge_dynamic = 0;
}

struct unrhdr *
new_unrhdr(int low, int high, struct mtx *mutex)
{
    struct unrhdr *header = 0;

    if (low > high)
        return 0;
    unr_lock();
    for (unsigned int index = 0; index < BSD_UNR_HEADER_SLOTS; ++index) {
        if (g_unr_header_used[index])
            continue;
        g_unr_header_used[index] = 1;
        header = &g_unr_headers[index];
        header->low = low;
        header->high = high;
        header->entries = 0;
        header->mutex = mutex;
        header->bridge_dynamic = 1;
        break;
    }
    unr_unlock();
    return header;
}

void
clear_unrhdr(struct unrhdr *header)
{
    unr_lock();
    unr_clear_locked(header);
    unr_unlock();
}

void
clean_unrhdr(struct unrhdr *header)
{
    clear_unrhdr(header);
}

void
clean_unrhdrl(struct unrhdr *header)
{
    clear_unrhdr(header);
}

void
delete_unrhdr(struct unrhdr *header)
{
    if (!header)
        return;
    unr_lock();
    unr_clear_locked(header);
    if (header->bridge_dynamic) {
        for (unsigned int index = 0; index < BSD_UNR_HEADER_SLOTS; ++index) {
            if (&g_unr_headers[index] != header)
                continue;
            g_unr_header_used[index] = 0;
            break;
        }
    }
    header->low = 0;
    header->high = -1;
    header->mutex = 0;
    header->bridge_dynamic = 0;
    unr_unlock();
}

static int
unr_allocate_locked(struct unrhdr *header, unsigned int requested,
    int specific)
{
    bsd_unr_entry_t **cursor;
    bsd_unr_entry_t *entry = 0;
    uint64_t candidate;

    if (!header || header->low > header->high || header->low < 0)
        return -1;
    candidate = specific ? requested : (unsigned int)header->low;
    if (candidate < (unsigned int)header->low ||
        candidate > (unsigned int)header->high)
        return -1;
    cursor = (bsd_unr_entry_t **)&header->entries;
    while (*cursor && (*cursor)->item < candidate) {
        if (!specific && (*cursor)->item == candidate)
            candidate++;
        cursor = &(*cursor)->next;
    }
    if (!specific) {
        while (*cursor && (*cursor)->item == candidate) {
            candidate++;
            cursor = &(*cursor)->next;
        }
        if (candidate > (unsigned int)header->high)
            return -1;
    } else if (*cursor && (*cursor)->item == candidate) {
        return -1;
    }
    for (unsigned int index = 0; index < BSD_UNR_ENTRY_SLOTS; ++index) {
        if (g_unr_entries[index].used)
            continue;
        entry = &g_unr_entries[index];
        entry->used = 1;
        break;
    }
    if (!entry)
        return -1;
    entry->item = (unsigned int)candidate;
    entry->next = *cursor;
    *cursor = entry;
    return (int)candidate;
}

int
alloc_unr(struct unrhdr *header)
{
    int item;

    unr_lock();
    item = unr_allocate_locked(header, 0, 0);
    unr_unlock();
    return item;
}

int
alloc_unrl(struct unrhdr *header)
{
    return alloc_unr(header);
}

int
alloc_unr_specific(struct unrhdr *header, unsigned int item)
{
    int result;

    unr_lock();
    result = unr_allocate_locked(header, item, 1);
    unr_unlock();
    return result;
}

void
free_unr(struct unrhdr *header, unsigned int item)
{
    bsd_unr_entry_t **cursor;

    if (!header)
        return;
    unr_lock();
    cursor = (bsd_unr_entry_t **)&header->entries;
    while (*cursor && (*cursor)->item < item)
        cursor = &(*cursor)->next;
    if (*cursor && (*cursor)->item == item) {
        bsd_unr_entry_t *entry = *cursor;

        *cursor = entry->next;
        entry->next = 0;
        entry->item = 0;
        entry->used = 0;
    }
    unr_unlock();
}

void *
bsd_memset(void *destination, int value, size_t length)
{
    unsigned char *bytes = destination;

    for (size_t index = 0; index < length; ++index)
        bytes[index] = (unsigned char)value;
    return destination;
}

void *
bsd_memcpy(void *destination, const void *source, size_t length)
{
    unsigned char *output = destination;
    const unsigned char *input = source;

    for (size_t index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

void *
bsd_memmove(void *destination, const void *source, size_t length)
{
    unsigned char *output = destination;
    const unsigned char *input = source;

    if (output == input || length == 0)
        return destination;
    if (output < input) {
        for (size_t index = 0; index < length; ++index)
            output[index] = input[index];
    } else {
        for (size_t index = length; index != 0; --index)
            output[index - 1] = input[index - 1];
    }
    return destination;
}

int
bsd_memcmp(const void *left, const void *right, size_t length)
{
    const unsigned char *left_bytes = left;
    const unsigned char *right_bytes = right;

    for (size_t index = 0; index < length; ++index) {
        if (left_bytes[index] != right_bytes[index])
            return left_bytes[index] < right_bytes[index] ? -1 : 1;
    }
    return 0;
}

void *
bsd_memchr(const void *memory, int value, size_t length)
{
    const unsigned char *bytes = memory;
    unsigned char selected = (unsigned char)value;

    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] == selected)
            return (void *)(uintptr_t)&bytes[index];
    }
    return 0;
}

size_t
bsd_strlen(const char *text)
{
    size_t length = 0;

    while (text[length] != '\0')
        ++length;
    return length;
}

size_t
bsd_strnlen(const char *text, size_t maximum)
{
    size_t length = 0;

    while (length < maximum && text[length] != '\0')
        ++length;
    return length;
}

char *
bsd_strrchr(const char *text, int character)
{
    const char *match = 0;
    char selected = (char)character;

    do {
        if (*text == selected)
            match = text;
    } while (*text++ != '\0');
    return (char *)(uintptr_t)match;
}

char *
bsd_strchr(const char *text, int character)
{
    char selected = (char)character;

    do {
        if (*text == selected)
            return (char *)(uintptr_t)text;
    } while (*text++ != '\0');
    return 0;
}

char *
bsd_strcpy(char *destination, const char *source)
{
    char *result = destination;

    while ((*destination++ = *source++) != '\0')
        ;
    return result;
}

char *
bsd_strncpy(char *destination, const char *source, size_t length)
{
    size_t index = 0;

    while (index < length && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
    while (index < length)
        destination[index++] = '\0';
    return destination;
}

char *
bsd_strcat(char *destination, const char *source)
{
    size_t offset = bsd_strlen(destination);

    (void)bsd_strlcpy(destination + offset, source, SIZE_MAX - offset);
    return destination;
}

char *
bsd_strstr(const char *text, const char *needle)
{
    size_t needle_length;

    if (!text || !needle)
        return 0;
    needle_length = bsd_strlen(needle);
    if (needle_length == 0)
        return (char *)(uintptr_t)text;
    while (*text != '\0') {
        if (*text == *needle &&
            bsd_strncmp(text, needle, needle_length) == 0)
            return (char *)(uintptr_t)text;
        ++text;
    }
    return 0;
}

char *
bsd_strsep(char **text, const char *delimiters)
{
    char *start;
    char *cursor;

    if (!text || !*text || !delimiters)
        return 0;
    start = *text;
    cursor = start;
    while (*cursor) {
        if (bsd_strchr(delimiters, *cursor)) {
            *cursor = '\0';
            *text = cursor + 1;
            return start;
        }
        ++cursor;
    }
    *text = 0;
    return start;
}

int
bsd_strcmp(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return (unsigned char)*left - (unsigned char)*right;
}

int
bsd_strncmp(const char *left, const char *right, size_t length)
{
    for (size_t index = 0; index < length; ++index) {
        unsigned char left_byte = (unsigned char)left[index];
        unsigned char right_byte = (unsigned char)right[index];

        if (left_byte != right_byte)
            return left_byte - right_byte;
        if (left_byte == '\0')
            return 0;
    }
    return 0;
}

int
bsd_strcasecmp(const char *left, const char *right)
{
    while (*left || *right) {
        unsigned char left_byte = (unsigned char)*left;
        unsigned char right_byte = (unsigned char)*right;

        if (left_byte >= 'A' && left_byte <= 'Z')
            left_byte = (unsigned char)(left_byte + ('a' - 'A'));
        if (right_byte >= 'A' && right_byte <= 'Z')
            right_byte = (unsigned char)(right_byte + ('a' - 'A'));
        if (left_byte != right_byte)
            return left_byte < right_byte ? -1 : 1;
        if (!*left)
            break;
        ++left;
        ++right;
    }
    return 0;
}

int
bsd_strncasecmp(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        unsigned char left_byte = (unsigned char)left[index];
        unsigned char right_byte = (unsigned char)right[index];

        if (left_byte >= 'A' && left_byte <= 'Z')
            left_byte = (unsigned char)(left_byte + ('a' - 'A'));
        if (right_byte >= 'A' && right_byte <= 'Z')
            right_byte = (unsigned char)(right_byte + ('a' - 'A'));
        if (left_byte != right_byte)
            return left_byte < right_byte ? -1 : 1;
        if (left_byte == '\0')
            return 0;
    }
    return 0;
}

char *
bsd_strcasestr(const char *text, const char *needle)
{
    size_t needle_length;

    if (!text || !needle)
        return 0;
    needle_length = bsd_strlen(needle);
    if (needle_length == 0)
        return (char *)text;
    for (; *text; ++text) {
        size_t index;
        for (index = 0; index < needle_length; ++index) {
            unsigned char left = (unsigned char)text[index];
            unsigned char right = (unsigned char)needle[index];

            if (left >= 'A' && left <= 'Z')
                left = (unsigned char)(left + ('a' - 'A'));
            if (right >= 'A' && right <= 'Z')
                right = (unsigned char)(right + ('a' - 'A'));
            if (left != right || left == '\0')
                break;
        }
        if (index == needle_length)
            return (char *)text;
    }
    return 0;
}

size_t
bsd_strlcpy(char *destination, const char *source, size_t capacity)
{
    size_t source_length = bsd_strlen(source);
    size_t copy_length =
        capacity == 0 ? 0 :
        (source_length < capacity - 1 ? source_length : capacity - 1);

    if (copy_length != 0)
        bsd_memcpy(destination, source, copy_length);
    if (capacity != 0)
        destination[copy_length] = '\0';
    return source_length;
}

size_t
bsd_strlcat(char *destination, const char *source, size_t capacity)
{
    size_t destination_length = 0;
    size_t source_length = bsd_strlen(source);

    while (destination_length < capacity &&
        destination[destination_length] != '\0')
        ++destination_length;
    if (destination_length == capacity)
        return capacity + source_length;
    (void)bsd_strlcpy(destination + destination_length, source,
        capacity - destination_length);
    return destination_length + source_length;
}

static void
format_character(bsd_format_output_t *output, char value)
{
    if (output->destination && output->capacity != 0 &&
        output->length < output->capacity - 1)
        output->destination[output->length] = value;
    ++output->length;
}

static void
format_repeat(bsd_format_output_t *output, char value, size_t count)
{
    while (count-- != 0)
        format_character(output, value);
}

static void
format_span(bsd_format_output_t *output, const char *text, size_t length)
{
    for (size_t index = 0; index < length; ++index)
        format_character(output, text[index]);
}

static size_t
format_unsigned_digits(char *buffer, uint64_t value, unsigned int base,
    int upper)
{
    static const char lower_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    static const char upper_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *digits = upper ? upper_digits : lower_digits;
    char reversed[65];
    size_t length = 0;

    do {
        reversed[length++] = digits[value % base];
        value /= base;
    } while (value != 0 && length < sizeof(reversed));
    for (size_t index = 0; index < length; ++index)
        buffer[index] = reversed[length - index - 1];
    return length;
}

static void
format_text(bsd_format_output_t *output, const char *text, int width,
    int precision, int left_adjust)
{
    size_t length = bsd_strlen(text);
    size_t padding;

    if (precision >= 0 && length > (size_t)precision)
        length = (size_t)precision;
    padding = width > (int)length ? (size_t)width - length : 0;
    if (!left_adjust)
        format_repeat(output, ' ', padding);
    format_span(output, text, length);
    if (left_adjust)
        format_repeat(output, ' ', padding);
}

static void
format_integer(bsd_format_output_t *output, uint64_t value,
    unsigned int base, int upper, int width, int precision,
    int left_adjust, int zero_pad, int alternate, char sign)
{
    char digits[65];
    char prefix[2];
    size_t digit_count =
        format_unsigned_digits(digits, value, base, upper);
    size_t prefix_count = 0;
    size_t zero_count;
    size_t padding;

    if (alternate && value != 0) {
        prefix[0] = '0';
        if (base == 16) {
            prefix[1] = upper ? 'X' : 'x';
            prefix_count = 2;
        } else if (base == 8) {
            prefix_count = 1;
        }
    }
    zero_count = precision > (int)digit_count ?
        (size_t)precision - digit_count : 0;
    if (zero_pad && !left_adjust && precision < 0) {
        size_t occupied = digit_count + prefix_count + (sign ? 1U : 0U);

        if (width > (int)occupied)
            zero_count = (size_t)width - occupied;
    }
    padding = width > (int)(digit_count + zero_count + prefix_count +
        (sign ? 1U : 0U)) ?
        (size_t)width - digit_count - zero_count - prefix_count -
        (sign ? 1U : 0U) : 0;
    if (!left_adjust)
        format_repeat(output, ' ', padding);
    if (sign)
        format_character(output, sign);
    format_span(output, prefix, prefix_count);
    format_repeat(output, '0', zero_count);
    format_span(output, digits, digit_count);
    if (left_adjust)
        format_repeat(output, ' ', padding);
}

enum bsd_format_length {
    BSD_FORMAT_DEFAULT,
    BSD_FORMAT_HH,
    BSD_FORMAT_H,
    BSD_FORMAT_L,
    BSD_FORMAT_LL,
    BSD_FORMAT_J,
    BSD_FORMAT_T,
    BSD_FORMAT_Z,
};

static void
format_bit_description(bsd_format_output_t *output, uint64_t value,
    const char *description)
{
    int first = 1;
    const unsigned char *cursor =
        (const unsigned char *)description;

    if (!cursor || *cursor == '\0')
        return;
    ++cursor;
    while (*cursor != '\0') {
        unsigned int marker = *cursor++;
        unsigned int bit;
        const unsigned char *name = cursor;

        if (marker >= 128)
            bit = marker & 0x7f;
        else if (marker != 0 && marker <= 32)
            bit = marker - 1;
        else
            break;
        while (*cursor > ' ' && *cursor < 127)
            ++cursor;
        if (bit < 64 && (value & (UINT64_C(1) << bit)) != 0) {
            format_character(output, first ? '<' : ',');
            format_span(output, (const char *)name,
                (size_t)(cursor - name));
            first = 0;
        }
    }
    if (!first)
        format_character(output, '>');
}

int
bsd_vsnprintf(char *destination, size_t capacity, const char *format,
    va_list arguments)
{
    bsd_format_output_t output = {
        .destination = destination,
        .capacity = capacity,
    };

    while (*format != '\0') {
        int width = 0;
        int precision = -1;
        int zero_pad = 0;
        int left_adjust = 0;
        int alternate = 0;
        char requested_sign = 0;
        enum bsd_format_length length = BSD_FORMAT_DEFAULT;
        char conversion;

        if (*format != '%') {
            format_character(&output, *format++);
            continue;
        }
        ++format;
        for (;;) {
            if (*format == '#')
                alternate = 1;
            else if (*format == '-')
                left_adjust = 1;
            else if (*format == '+')
                requested_sign = '+';
            else if (*format == ' ')
                requested_sign = requested_sign ? requested_sign : ' ';
            else if (*format == '0')
                zero_pad = 1;
            else
                break;
            ++format;
        }
        if (*format == '*') {
            width = va_arg(arguments, int);
            if (width < 0) {
                left_adjust = 1;
                width = -width;
            }
            ++format;
        }
        while (*format >= '0' && *format <= '9') {
            width = width * 10 + (*format - '0');
            ++format;
        }
        if (*format == '.') {
            ++format;
            precision = 0;
            if (*format == '*') {
                precision = va_arg(arguments, int);
                if (precision < 0)
                    precision = -1;
                ++format;
            } else {
                while (*format >= '0' && *format <= '9') {
                    precision = precision * 10 + (*format - '0');
                    ++format;
                }
            }
        }
        if (format[0] == 'h' && format[1] == 'h') {
            length = BSD_FORMAT_HH;
            format += 2;
        } else if (*format == 'h') {
            length = BSD_FORMAT_H;
            ++format;
        } else if (format[0] == 'l' && format[1] == 'l') {
            length = BSD_FORMAT_LL;
            format += 2;
        } else if (*format == 'l' || *format == 'q') {
            length = BSD_FORMAT_L;
            if (*format == 'q')
                length = BSD_FORMAT_LL;
            ++format;
        } else if (*format == 'j') {
            length = BSD_FORMAT_J;
            ++format;
        } else if (*format == 't') {
            length = BSD_FORMAT_T;
            ++format;
        } else if (*format == 'z') {
            length = BSD_FORMAT_Z;
            ++format;
        }
        conversion = *format == '\0' ? '\0' : *format++;

        switch (conversion) {
        case 'd':
        case 'i': {
            int64_t value;

            if (length == BSD_FORMAT_LL)
                value = va_arg(arguments, long long);
            else if (length == BSD_FORMAT_L)
                value = va_arg(arguments, long);
            else if (length == BSD_FORMAT_J)
                value = va_arg(arguments, intmax_t);
            else if (length == BSD_FORMAT_T ||
                length == BSD_FORMAT_Z)
                value = va_arg(arguments, ptrdiff_t);
            else
                value = va_arg(arguments, int);
            if (length == BSD_FORMAT_H)
                value = (short)value;
            else if (length == BSD_FORMAT_HH)
                value = (signed char)value;
            if (value < 0) {
                uint64_t magnitude =
                    (uint64_t)(-(value + 1)) + 1;

                format_integer(&output, magnitude, 10, 0, width,
                    precision, left_adjust, zero_pad, 0, '-');
            } else {
                format_integer(&output, (uint64_t)value, 10, 0, width,
                    precision, left_adjust, zero_pad, 0, requested_sign);
            }
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        case 'o': {
            uint64_t value;
            unsigned int base =
                conversion == 'x' || conversion == 'X' ? 16U :
                (conversion == 'o' ? 8U : 10U);

            if (length == BSD_FORMAT_LL)
                value = va_arg(arguments, unsigned long long);
            else if (length == BSD_FORMAT_L)
                value = va_arg(arguments, unsigned long);
            else if (length == BSD_FORMAT_J)
                value = va_arg(arguments, uintmax_t);
            else if (length == BSD_FORMAT_T)
                value = (uint64_t)va_arg(arguments, ptrdiff_t);
            else if (length == BSD_FORMAT_Z)
                value = va_arg(arguments, size_t);
            else
                value = va_arg(arguments, unsigned int);
            if (length == BSD_FORMAT_H)
                value = (unsigned short)value;
            else if (length == BSD_FORMAT_HH)
                value = (unsigned char)value;
            format_integer(&output, value, base, conversion == 'X',
                width, precision, left_adjust, zero_pad, alternate, 0);
            break;
        }
        case 'p': {
            uintptr_t value = (uintptr_t)va_arg(arguments, void *);

            format_integer(&output, (uint64_t)value, 16, 0, width,
                precision, left_adjust, zero_pad, 1, 0);
            break;
        }
        case 's': {
            const char *text = va_arg(arguments, const char *);

            format_text(&output, text ? text : "(null)", width,
                precision, left_adjust);
            break;
        }
        case 'c': {
            size_t padding = width > 1 ? (size_t)width - 1 : 0;

            if (!left_adjust)
                format_repeat(&output, ' ', padding);
            format_character(&output, (char)va_arg(arguments, int));
            if (left_adjust)
                format_repeat(&output, ' ', padding);
            break;
        }
        case 'b': {
            uint64_t value;
            const char *description;
            unsigned int base;
            size_t start;

            if (length == BSD_FORMAT_LL)
                value = va_arg(arguments, unsigned long long);
            else if (length == BSD_FORMAT_L)
                value = va_arg(arguments, unsigned long);
            else if (length == BSD_FORMAT_J)
                value = va_arg(arguments, uintmax_t);
            else if (length == BSD_FORMAT_T)
                value = (uint64_t)va_arg(arguments, ptrdiff_t);
            else if (length == BSD_FORMAT_Z)
                value = va_arg(arguments, size_t);
            else
                value = va_arg(arguments, unsigned int);
            if (length == BSD_FORMAT_H)
                value = (unsigned short)value;
            else if (length == BSD_FORMAT_HH)
                value = (unsigned char)value;
            description = va_arg(arguments, const char *);
            base = description && (unsigned char)description[0] >= 2 &&
                (unsigned char)description[0] <= 36 ?
                (unsigned char)description[0] : 10U;
            start = output.length;
            format_integer(&output, value, base, 0, 0, precision,
                1, zero_pad, alternate, 0);
            if (value != 0)
                format_bit_description(&output, value, description);
            if (width > (int)(output.length - start))
                format_repeat(&output, ' ',
                    (size_t)width - (output.length - start));
            break;
        }
        case 'D': {
            const unsigned char *bytes =
                va_arg(arguments, const unsigned char *);
            const char *separator = va_arg(arguments, const char *);
            int count = width == 0 ? 16 : width;
            static const char hex[] = "0123456789ABCDEF";

            for (int index = 0; index < count; ++index) {
                format_character(&output, hex[bytes[index] >> 4]);
                format_character(&output, hex[bytes[index] & 0x0f]);
                if (index + 1 != count && separator)
                    format_span(&output, separator,
                        bsd_strlen(separator));
            }
            break;
        }
        case '%':
            format_character(&output, '%');
            break;
        case '\0':
            --format;
            break;
        default:
            format_character(&output, '%');
            format_character(&output, conversion);
            break;
        }
    }
    if (capacity != 0) {
        size_t terminator =
            output.length < capacity ? output.length : capacity - 1;
        if (destination)
            destination[terminator] = '\0';
    }
    return output.length > (size_t)INT32_MAX ? INT32_MAX : (int)output.length;
}

int
bsd_vasprintf(char **result, struct malloc_type *type, const char *format,
    va_list arguments)
{
    va_list measure_arguments;
    va_list render_arguments;
    char *buffer;
    int length;

    if (!result || !format)
        return -1;
    *result = 0;
    va_copy(measure_arguments, arguments);
    length = bsd_vsnprintf(0, 0, format, measure_arguments);
    va_end(measure_arguments);
    if (length < 0 || (size_t)length == SIZE_MAX)
        return -1;
    (void)type;
    buffer = bsd_kmalloc((size_t)length + 1, BSD_M_NOWAIT);
    if (!buffer)
        return -1;
    va_copy(render_arguments, arguments);
    (void)bsd_vsnprintf(buffer, (size_t)length + 1, format,
        render_arguments);
    va_end(render_arguments);
    *result = buffer;
    return length;
}

int
bsd_asprintf(char **result, struct malloc_type *type, const char *format, ...)
{
    va_list arguments;
    int length;

    va_start(arguments, format);
    length = bsd_vasprintf(result, type, format, arguments);
    va_end(arguments);
    return length;
}

int
bsd_vprintf(const char *format, va_list arguments)
{
    char buffer[1024];
    int result;

    if (!format)
        return -1;
    result = bsd_vsnprintf(buffer, sizeof(buffer), format, arguments);
    printf("%s", buffer);
    return result;
}

void
bsd_vlog(int priority, const char *format, va_list arguments)
{
    (void)priority;
    (void)bsd_vprintf(format, arguments);
}

void
bsd_log(int priority, const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    bsd_vlog(priority, format, arguments);
    va_end(arguments);
}

int
bsd_printf(const char *format, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = bsd_vprintf(format, arguments);
    va_end(arguments);
    return result;
}

void
bsd_panic(const char *format, ...)
{
    va_list arguments;

    bsd_printf("[bsd-bridge] panic: ");
    va_start(arguments, format);
    (void)bsd_vprintf(format, arguments);
    va_end(arguments);
    bsd_printf("\n");
    bsd_bridge_panic_stop();
    __builtin_unreachable();
}

int
bsd_snprintf(char *destination, size_t capacity, const char *format, ...)
{
    int result;
    va_list arguments;

    va_start(arguments, format);
    result = bsd_vsnprintf(destination, capacity, format, arguments);
    va_end(arguments);
    return result;
}

int
bsd_sprintf(char *destination, const char *format, ...)
{
    va_list arguments;
    int result;

    if (!destination || !format)
        return -1;
    va_start(arguments, format);
    result = bsd_vsnprintf(destination, SIZE_MAX, format, arguments);
    va_end(arguments);
    return result;
}

unsigned long
bsd_strtoul(const char *text, char **end, int base)
{
    const char *cursor = text;
    unsigned long value = 0;
    unsigned long maximum = ~0ul;
    int selected_base = base;
    int negative = 0;
    int overflow = 0;
    int converted = 0;

    if (!text || (base != 0 && (base < 2 || base > 36))) {
        if (end)
            *end = (char *)(uintptr_t)text;
        return 0;
    }
    while (*cursor == ' ' ||
        (*cursor >= '\t' && *cursor <= '\r'))
        ++cursor;
    if (*cursor == '+' || *cursor == '-') {
        negative = *cursor == '-';
        ++cursor;
    }
    if (selected_base == 0) {
        if (cursor[0] == '0' &&
            (cursor[1] == 'x' || cursor[1] == 'X') &&
            ((cursor[2] >= '0' && cursor[2] <= '9') ||
            (cursor[2] >= 'a' && cursor[2] <= 'f') ||
            (cursor[2] >= 'A' && cursor[2] <= 'F'))) {
            selected_base = 16;
            cursor += 2;
        } else {
            selected_base = cursor[0] == '0' ? 8 : 10;
        }
    } else if (selected_base == 16 && cursor[0] == '0' &&
        (cursor[1] == 'x' || cursor[1] == 'X') &&
        ((cursor[2] >= '0' && cursor[2] <= '9') ||
        (cursor[2] >= 'a' && cursor[2] <= 'f') ||
        (cursor[2] >= 'A' && cursor[2] <= 'F'))) {
        cursor += 2;
    }
    for (;;) {
        unsigned int digit;
        char character = *cursor;

        if (character >= '0' && character <= '9')
            digit = (unsigned int)(character - '0');
        else if (character >= 'a' && character <= 'z')
            digit = (unsigned int)(character - 'a') + 10u;
        else if (character >= 'A' && character <= 'Z')
            digit = (unsigned int)(character - 'A') + 10u;
        else
            break;
        if (digit >= (unsigned int)selected_base)
            break;
        converted = 1;
        if (value > (maximum - digit) / (unsigned int)selected_base) {
            value = maximum;
            overflow = 1;
        } else if (!overflow) {
            value = value * (unsigned int)selected_base + digit;
        }
        ++cursor;
    }
    if (end)
        *end = (char *)(uintptr_t)(converted ? cursor : text);
    if (!converted)
        return 0;
    if (negative && !overflow)
        return 0ul - value;
    return value;
}

long
bsd_strtol(const char *text, char **end, int base)
{
    return (long)bsd_strtoq(text, end, base);
}

uint64_t
bsd_strtouq(const char *text, char **end, int base)
{
    return (uint64_t)bsd_strtoul(text, end, base);
}

int64_t
bsd_strtoq(const char *text, char **end, int base)
{
    const char *cursor = text;
    uint64_t magnitude = 0;
    uint64_t limit;
    int selected_base = base;
    int negative = 0;
    int overflow = 0;
    int converted = 0;

    if (!text || (base != 0 && (base < 2 || base > 36))) {
        if (end)
            *end = (char *)(uintptr_t)text;
        return 0;
    }
    while (*cursor == ' ' ||
        (*cursor >= '\t' && *cursor <= '\r'))
        ++cursor;
    if (*cursor == '+' || *cursor == '-') {
        negative = *cursor == '-';
        ++cursor;
    }
    if (selected_base == 0) {
        if (cursor[0] == '0' &&
            (cursor[1] == 'x' || cursor[1] == 'X') &&
            ((cursor[2] >= '0' && cursor[2] <= '9') ||
            (cursor[2] >= 'a' && cursor[2] <= 'f') ||
            (cursor[2] >= 'A' && cursor[2] <= 'F'))) {
            selected_base = 16;
            cursor += 2;
        } else {
            selected_base = cursor[0] == '0' ? 8 : 10;
        }
    } else if (selected_base == 16 && cursor[0] == '0' &&
        (cursor[1] == 'x' || cursor[1] == 'X') &&
        ((cursor[2] >= '0' && cursor[2] <= '9') ||
        (cursor[2] >= 'a' && cursor[2] <= 'f') ||
        (cursor[2] >= 'A' && cursor[2] <= 'F'))) {
        cursor += 2;
    }
    limit = negative ? (UINT64_C(1) << 63) : INT64_MAX;
    for (;;) {
        unsigned int digit;
        char character = *cursor;

        if (character >= '0' && character <= '9')
            digit = (unsigned int)(character - '0');
        else if (character >= 'a' && character <= 'z')
            digit = (unsigned int)(character - 'a') + 10u;
        else if (character >= 'A' && character <= 'Z')
            digit = (unsigned int)(character - 'A') + 10u;
        else
            break;
        if (digit >= (unsigned int)selected_base)
            break;
        converted = 1;
        if (magnitude > (limit - digit) / (unsigned int)selected_base) {
            magnitude = limit;
            overflow = 1;
        } else if (!overflow) {
            magnitude = magnitude * (unsigned int)selected_base + digit;
        }
        ++cursor;
    }
    if (end)
        *end = (char *)(uintptr_t)(converted ? cursor : text);
    if (!converted)
        return 0;
    if (overflow)
        return negative ? INT64_MIN : INT64_MAX;
    if (negative) {
        if (magnitude == (UINT64_C(1) << 63))
            return INT64_MIN;
        return -(int64_t)magnitude;
    }
    return (int64_t)magnitude;
}

int
bsd_copyin(const void *source, void *destination, size_t length)
{
    if ((!source || !destination) && length != 0)
        return 14;
    if (length != 0)
        bsd_memcpy(destination, source, length);
    return 0;
}

int
bsd_copyout(const void *source, void *destination, size_t length)
{
    return bsd_copyin(source, destination, length);
}

int
bsd_copyinstr(const void *source, void *destination, size_t capacity,
    size_t *copied)
{
    const char *input = source;
    char *output = destination;
    size_t index;

    if (!input || !output || capacity == 0)
        return 14;
    for (index = 0; index < capacity; ++index) {
        int error = bsd_copyin(input + index, output + index, 1);

        if (error)
            return error;
        if (output[index] == '\0') {
            if (copied)
                *copied = index + 1;
            return 0;
        }
    }
    if (copied)
        *copied = capacity;
    return 63;
}

int
bsd_fueword(const void *source, long *value)
{
    return bsd_copyin(source, value, sizeof(*value)) == 0 ? 0 : -1;
}

int
bsd_fueword32(const void *source, uint32_t *value)
{
    return bsd_copyin(source, value, sizeof(*value)) == 0 ? 0 : -1;
}

int
bsd_suword16(void *destination, uint16_t value)
{
    return bsd_copyout(&value, destination, sizeof(value)) == 0 ? 0 : -1;
}

int
bsd_suword32(void *destination, uint32_t value)
{
    return bsd_copyout(&value, destination, sizeof(value)) == 0 ? 0 : -1;
}

void
hexdump(const void *pointer, int length, const char *header, int flags)
{
    const unsigned char *bytes = pointer;
    int columns = flags & HD_COLUMN_MASK;
    char delimiter = (char)((flags & HD_DELIM_MASK) >> 8);

    if (!bytes || length <= 0)
        return;
    if (columns == 0)
        columns = 16;
    if (delimiter == 0)
        delimiter = ' ';
    for (int offset = 0; offset < length; offset += columns) {
        if (header)
            bsd_printf("%s", header);
        if ((flags & HD_OMIT_COUNT) == 0)
            bsd_printf("%04x  ", offset);
        if ((flags & HD_OMIT_HEX) == 0) {
            for (int column = 0; column < columns; ++column) {
                int index = offset + column;

                if (index < length)
                    bsd_printf("%c%02x", delimiter, bytes[index]);
                else
                    bsd_printf("   ");
            }
        }
        if ((flags & HD_OMIT_CHARS) == 0) {
            bsd_printf("  |");
            for (int column = 0; column < columns; ++column) {
                int index = offset + column;

                if (index >= length)
                    bsd_printf(" ");
                else if (bytes[index] >= ' ' && bytes[index] <= '~')
                    bsd_printf("%c", bytes[index]);
                else
                    bsd_printf(".");
            }
            bsd_printf("|");
        }
        bsd_printf("\n");
    }
}

int
bsd_ffs(int value)
{
    return value == 0 ? 0 : __builtin_ctz((unsigned int)value) + 1;
}

int
bsd_ffsll(long long value)
{
    return value == 0 ? 0 :
        __builtin_ctzll((unsigned long long)value) + 1;
}

int
bsd_fls(int value)
{
    return value == 0 ? 0 :
        (int)(sizeof(unsigned int) * 8U) -
        __builtin_clz((unsigned int)value);
}

int
bsd_ffsl(long value)
{
    return value == 0 ? 0 : __builtin_ctzl((unsigned long)value) + 1;
}

int
bsd_flsl(long value)
{
    return value == 0 ? 0 :
        (int)(sizeof(unsigned long) * 8U) -
        __builtin_clzl((unsigned long)value);
}

int
bsd_flsll(long long value)
{
    unsigned long long selected = (unsigned long long)value;

    return selected == 0 ? 0 :
        (int)(sizeof(selected) * 8u -
        (unsigned int)__builtin_clzll(selected));
}

uint64_t
bsd_roundup_power_of_two(uint64_t value)
{
    if (value <= 1)
        return 1;
    if (value > (UINT64_C(1) << 63))
        return 0;
    return UINT64_C(1) << (64U - (unsigned int)__builtin_clzll(value - 1));
}

uint64_t
bsd_rounddown_power_of_two(uint64_t value)
{
    if (value == 0)
        return 0;
    return UINT64_C(1) << (63U - (unsigned int)__builtin_clzll(value));
}

void
bsd_bridge_panic_stop(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    abort();
#elif defined(__aarch64__)
    __asm __volatile("msr daifset, #0xf" : : : "memory");
    for (;;)
        __asm __volatile("wfi");
#elif defined(__x86_64__)
    __asm __volatile("cli" : : : "memory");
    for (;;)
        __asm __volatile("hlt");
#else
#error "Unsupported EdgeOS FreeBSD driver bridge architecture"
#endif
}
