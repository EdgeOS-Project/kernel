/* SPDX-License-Identifier: MPL-2.0 */
/* Core runtime helpers for the EdgeOS FreeBSD driver bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYSTM_H
#define EDGEOS_COMPAT_FREEBSD_SYSTM_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#define HD_COLUMN_MASK 0xff
#define HD_DELIM_MASK 0xff00
#define HD_OMIT_COUNT (1 << 16)
#define HD_OMIT_HEX (1 << 17)
#define HD_OMIT_CHARS (1 << 18)

struct mtx;
struct malloc_type;
struct unrhdr {
    int low;
    int high;
    void *entries;
    struct mtx *mutex;
    uint8_t bridge_dynamic;
};

struct unrhdr *new_unrhdr(int low, int high, struct mtx *mutex);
void init_unrhdr(struct unrhdr *header, int low, int high,
    struct mtx *mutex);
void delete_unrhdr(struct unrhdr *header);
void clear_unrhdr(struct unrhdr *header);
void clean_unrhdr(struct unrhdr *header);
void clean_unrhdrl(struct unrhdr *header);
int alloc_unr(struct unrhdr *header);
int alloc_unr_specific(struct unrhdr *header, unsigned int item);
int alloc_unrl(struct unrhdr *header);
void free_unr(struct unrhdr *header, unsigned int item);

void *bsd_memset(void *destination, int value, size_t length);
void *bsd_memcpy(void *destination, const void *source, size_t length);
void *bsd_memmove(void *destination, const void *source, size_t length);
int bsd_memcmp(const void *left, const void *right, size_t length);
void *bsd_memchr(const void *memory, int value, size_t length);
size_t bsd_strlen(const char *text);
size_t bsd_strnlen(const char *text, size_t maximum);
char *bsd_strrchr(const char *text, int character);
char *bsd_strchr(const char *text, int character);
char *bsd_strcpy(char *destination, const char *source);
char *bsd_strncpy(char *destination, const char *source, size_t length);
char *bsd_strcat(char *destination, const char *source);
char *bsd_strstr(const char *text, const char *needle);
char *bsd_strsep(char **text, const char *delimiters);
int bsd_strcmp(const char *left, const char *right);
int bsd_strncmp(const char *left, const char *right, size_t length);
int bsd_strcasecmp(const char *left, const char *right);
int bsd_strncasecmp(const char *left, const char *right, size_t length);
char *bsd_strcasestr(const char *text, const char *needle);
size_t bsd_strlcpy(char *destination, const char *source, size_t capacity);
size_t bsd_strlcat(char *destination, const char *source, size_t capacity);

int bsd_vsnprintf(char *destination, size_t capacity, const char *format,
    va_list arguments);
int bsd_vasprintf(char **result, struct malloc_type *type,
    const char *format, va_list arguments);
int bsd_vprintf(const char *format, va_list arguments);
void bsd_vlog(int priority, const char *format, va_list arguments);
void bsd_log(int priority, const char *format, ...);
int bsd_printf(const char *format, ...);
void bsd_panic(const char *format, ...)
    __attribute__((noreturn, format(printf, 1, 2)));
int bsd_snprintf(char *destination, size_t capacity, const char *format, ...);
int bsd_sprintf(char *destination, const char *format, ...);
unsigned long bsd_strtoul(const char *text, char **end, int base);
long bsd_strtol(const char *text, char **end, int base);
uint64_t bsd_strtouq(const char *text, char **end, int base);
int64_t bsd_strtoq(const char *text, char **end, int base);
int bsd_copyin(const void *source, void *destination, size_t length);
int bsd_copyout(const void *source, void *destination, size_t length);
int bsd_copyinstr(const void *source, void *destination, size_t capacity,
    size_t *copied);
int bsd_fueword(const void *source, long *value);
int bsd_fueword32(const void *source, uint32_t *value);
int bsd_suword16(void *destination, uint16_t value);
int bsd_suword32(void *destination, uint32_t value);
void bsd_critical_enter(void);
void bsd_critical_exit(void);
char *kern_getenv(const char *name);
void freeenv(char *environment);
int getenv_int(const char *name, int *data);

int bsd_ffs(int value);
int bsd_ffsll(long long value);
int bsd_fls(int value);
int bsd_ffsl(long value);
int bsd_flsl(long value);
int bsd_flsll(long long value);
uint64_t bsd_roundup_power_of_two(uint64_t value);
uint64_t bsd_rounddown_power_of_two(uint64_t value);

void bsd_bridge_panic_stop(void) __attribute__((noreturn));

#endif
