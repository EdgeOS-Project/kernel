/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD kernel runtime interface for unmodified driver sources. */

#ifndef _SYS_SYSTM_H_
#define _SYS_SYSTM_H_

#include <stdbool.h>
#include <sys/param.h>
#include <sys/stdarg.h>
#include <sys/types.h>
#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/cpufunc.h>
#include <edgeos/root_mount.h>
#include <edgeos/sleep.h>
#include <edgeos/systm.h>
#include <edgeos/hash.h>
#include <sys/callout.h>
#include <sys/cpuset.h>
#include <sys/kassert.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sched.h>
#include <sys/sysctl.h>

uint32_t arc4random(void);
void arc4random_buf(void *buffer, size_t length);
void hexdump(const void *pointer, int length, const char *header, int flags);
int sysbeep(int hertz, sbintime_t duration);
int sscanf(const char *input, const char *format, ...);
int vsscanf(const char *input, const char *format, va_list arguments);
int bsd_vasprintf(char **result, struct malloc_type *type, const char *format,
    va_list arguments);
int bsd_asprintf(char **result, struct malloc_type *type, const char *format,
    ...);

#define vasprintf bsd_vasprintf
#define asprintf bsd_asprintf

#ifndef HD_COLUMN_MASK
#define HD_COLUMN_MASK 0xff
#define HD_DELIM_MASK 0xff00
#define HD_OMIT_COUNT (1 << 16)
#define HD_OMIT_HEX (1 << 17)
#define HD_OMIT_CHARS (1 << 18)
#endif

#define __diagused __unused
#define __witness_used __unused
#ifndef __read_mostly
#define __read_mostly __attribute__((section(".data.read_mostly")))
#endif

#define memset(destination, value, length) \
    bsd_memset((destination), (value), (length))
#define memcpy(destination, source, length) \
    bsd_memcpy((destination), (source), (length))
#define memmove(destination, source, length) \
    bsd_memmove((destination), (source), (length))
#define memcmp(left, right, length) bsd_memcmp((left), (right), (length))
#define bcmp(left, right, length) bsd_memcmp((left), (right), (length))
#define memchr(memory, value, length) bsd_memchr((memory), (value), (length))
#define bzero(destination, length) bsd_memset((destination), 0, (length))
#define bcopy(source, destination, length) \
    bsd_memmove((destination), (source), (length))
#define ovbcopy(source, destination, length) \
    bsd_memmove((destination), (source), (length))

#define strlen(text) bsd_strlen(text)
#define strnlen(text, maximum) bsd_strnlen((text), (maximum))
#define strrchr(text, character) bsd_strrchr((text), (character))
#define strchr(text, character) bsd_strchr((text), (character))
#define strcpy(destination, source) bsd_strcpy((destination), (source))
#define strncpy(destination, source, length) \
    bsd_strncpy((destination), (source), (length))
#define strcat(destination, source) bsd_strcat((destination), (source))
#define strstr(text, needle) bsd_strstr((text), (needle))
#define strsep(text, delimiters) bsd_strsep((text), (delimiters))
#define strcmp(left, right) bsd_strcmp((left), (right))
#define strncmp(left, right, length) bsd_strncmp((left), (right), (length))
#define strcasecmp(left, right) bsd_strcasecmp((left), (right))
#define strncasecmp(left, right, length) \
    bsd_strncasecmp((left), (right), (length))
#define strcasestr(text, needle) bsd_strcasestr((text), (needle))
#define strlcpy(destination, source, capacity) \
    bsd_strlcpy((destination), (source), (capacity))
#define strlcat(destination, source, capacity) \
    bsd_strlcat((destination), (source), (capacity))
#define snprintf(destination, capacity, ...) \
    bsd_snprintf((destination), (capacity), __VA_ARGS__)
#define vsnprintf(destination, capacity, format, arguments) \
    bsd_vsnprintf((destination), (capacity), (format), (arguments))
#define sprintf(destination, ...) bsd_sprintf((destination), __VA_ARGS__)
#define vprintf(format, arguments) bsd_vprintf((format), (arguments))
#define printf(...) bsd_printf(__VA_ARGS__)
#define vlog(priority, format, arguments) \
    bsd_vlog((priority), (format), (arguments))
#define log(priority, ...) bsd_log((priority), __VA_ARGS__)
#define strtoul(text, end, base) bsd_strtoul((text), (end), (base))
#define strtouq bsd_strtouq
#define strtol(text, end, base) bsd_strtol((text), (end), (base))
#define strtoq bsd_strtoq
#define copyin(source, destination, length) \
    bsd_copyin((source), (destination), (length))
#define copyout(source, destination, length) \
    bsd_copyout((source), (destination), (length))
#define copyinstr(source, destination, capacity, copied) \
    bsd_copyinstr((source), (destination), (capacity), (copied))
#define fueword(source, value) bsd_fueword((source), (value))
#define fueword32(source, value) bsd_fueword32((source), (value))
#define suword16(destination, value) bsd_suword16((destination), (value))
#define suword32(destination, value) bsd_suword32((destination), (value))
#define critical_enter() bsd_critical_enter()
#define critical_exit() bsd_critical_exit()

static inline intrmask_t
spltty(void)
{
    return 0;
}

static inline void
splx(intrmask_t level __unused)
{
}

#define ffs(value) bsd_ffs(value)
#define ffsll(value) bsd_ffsll(value)
#define fls(value) bsd_fls(value)
#define ffsl(value) bsd_ffsl(value)
#define flsl(value) bsd_flsl(value)
#define flsll(value) bsd_flsll(value)
#define roundup_pow_of_two(value) \
    ((__typeof__(value))bsd_roundup_power_of_two((uint64_t)(value)))
#define rounddown_pow_of_two(value) \
    ((__typeof__(value))bsd_rounddown_power_of_two((uint64_t)(value)))
#define min(left, right) ({                 \
    __typeof__(left) _min_left = (left);    \
    __typeof__(right) _min_right = (right); \
    _min_left < _min_right ? _min_left : _min_right; \
})
#define max(left, right) ({                 \
    __typeof__(left) _max_left = (left);    \
    __typeof__(right) _max_right = (right); \
    _max_left > _max_right ? _max_left : _max_right; \
})
#define imin(left, right) ((left) < (right) ? (left) : (right))
#define imax(left, right) ((left) > (right) ? (left) : (right))
#define lmax(left, right) ((long)(left) > (long)(right) ? \
    (long)(left) : (long)(right))
#define qmin(left, right) ((quad_t)(left) < (quad_t)(right) ? \
    (quad_t)(left) : (quad_t)(right))
#ifndef EDGEOS_BSD_DRIVER_PROVIDES_ABS
#define abs(value) ((value) < 0 ? -(value) : (value))
#endif

static inline int64_t
abs64(int64_t value)
{
    return value < 0 ? -value : value;
}

char *kern_getenv(const char *name);
void freeenv(char *environment);
int getenv_int(const char *name, int *data);
int getenv_ulong(const char *name, unsigned long *data);
int getenv_uint64(const char *name, uint64_t *data);
int getenv_bool(const char *name, bool *data);
int getenv_array(const char *name, void *data, int size, int *result_size,
    int type_size, bool allow_signed);
int kern_setenv(const char *name, const char *value);
int kern_unsetenv(const char *name);
int testenv(const char *name);

#define GETENV_UNSIGNED false
#define GETENV_SIGNED true

#define CTASSERT(expression) _Static_assert((expression), #expression)

extern int hz;
extern const int osreldate;
extern const char osrelease[];
extern const char ostype[];
extern int bootverbose;
struct eventtimer;
void cpu_et_frequency(struct eventtimer *eventtimer, uint64_t frequency);
extern int cold;
extern int rebooting;
extern int dumping;
extern u_long maxphys;
extern u_long physmem;
extern long realmem;

enum VM_GUEST {
    VM_GUEST_NO = 0,
    VM_GUEST_VM,
    VM_GUEST_XEN,
    VM_GUEST_HV,
    VM_GUEST_VMWARE,
    VM_GUEST_KVM,
    VM_GUEST_BHYVE,
    VM_GUEST_VBOX,
    VM_GUEST_PARALLELS,
    VM_GUEST_NVMM,
    VM_GUEST_LAST,
};

extern int vm_guest;

void arc4rand(void *buffer, unsigned int length, int reseed);
void shutdown_nice(int howto);
uint64_t cpu_ticks(void);
uint64_t cputick2usec(uint64_t tick);

#define DELAY(microseconds) bsd_delay(microseconds)
#define pause(wait_message, timeout_ticks) \
    bsd_pause((wait_message), (timeout_ticks))
#define pause_sig(wait_message, timeout_ticks) \
    bsd_pause_sig((wait_message), (timeout_ticks))
#define pause_sbt(wait_message, sleep_time, precision, flags) \
    bsd_pause_sbt((wait_message), (sleep_time), (precision), (flags))
#define msleep(channel, mutex, priority, wait_message, timeout_ticks) \
    bsd_msleep((channel), (mutex), (priority), (wait_message), \
        (timeout_ticks))
#define msleep_spin(channel, mutex, wait_message, timeout_ticks) \
    bsd_msleep((channel), (mutex), 0, (wait_message), (timeout_ticks))
#define msleep_sbt(channel, mutex, priority, wait_message, sbt, precision, flags) \
    bsd_msleep_sbt((channel), (mutex), (priority), (wait_message), \
        (sbt), (precision), (flags))
#define tsleep(channel, priority, wait_message, timeout_ticks) \
    bsd_msleep((channel), (struct mtx *)0, (priority), (wait_message), \
        (timeout_ticks))
#define tsleep_sbt(channel, priority, wait_message, sbt, precision, flags) \
    bsd_tsleep_sbt((channel), (priority), (wait_message), (sbt), \
        (precision), (flags))
#define wakeup(channel) bsd_wakeup(channel)
#define wakeup_one(channel) bsd_wakeup_one(channel)

#include <sys/libkern.h>

#endif
