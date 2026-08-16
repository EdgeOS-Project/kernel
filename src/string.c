#include "string.h"
#include <stdint.h>
#include "types.h"

void *memset(void *dst, char c, uint32 n) {
    void *ret = dst;
    uintptr_t d = (uintptr_t)dst;
    uint8_t byte = (uint8_t)c;
    uint64_t qword = 0x0101010101010101ULL * (uint64_t)byte;

    while (n && (d & 7u)) {
        *(uint8_t *)d = byte;
        d++;
        n--;
    }
    if (n >= 8) {
#if defined(__x86_64__)
        uint32 qwords = n / 8u;
        /*
         * Linux keeps DF clear on kernel entry, but this primitive is a last
         * line of defense for early boot and any hand-written entry path.  A
         * stale DF makes rep stosq walk backward and corrupt adjacent kernel
         * state.
         */
        __asm__ __volatile__(
            "cld; rep stosq"
            : "+D"(d), "+c"(qwords)
            : "a"(qword)
            : "memory");
        n &= 7u;
#elif defined(__aarch64__)
        while (n >= 8) {
            *(uint64_t *)d = qword;
            d += 8;
            n -= 8;
        }
#else
#error "memset needs an architecture implementation"
#endif
    }
    while (n) {
        *(uint8_t *)d = byte;
        d++;
        n--;
    }
    return ret;
}

void *memcpy(void *dst, const void *src, uint32 n) {
    void *ret = dst;
    uintptr_t d = (uintptr_t)dst;
    uintptr_t s = (uintptr_t)src;
    if (n >= 8 && ((d | s) & 7u) == 0) {
#if defined(__x86_64__)
        uint32 qwords = n / 8u;
        /*
         * User programs may set DF.  Kernel memcpy must never inherit that
         * state: ext4/XFCE exposed backward rep movsq as stack-local
         * corruption when copying on-disk descriptors next to saved pointers.
         */
        __asm__ __volatile__(
            "cld; rep movsq"
            : "+D"(d), "+S"(s), "+c"(qwords)
            :
            : "memory");
        n &= 7u;
#elif defined(__aarch64__)
        while (n >= 8) {
            *(uint64_t *)d = *(const uint64_t *)s;
            d += 8;
            s += 8;
            n -= 8;
        }
#else
#error "memcpy needs an architecture implementation"
#endif
    }
    while (n) {
        *(uint8_t *)d = *(const uint8_t *)s;
        d++;
        s++;
        n--;
    }
    return ret;
}


void *memmove(void *dst, const void *src, uint32 n) {
    uint8 *d = (uint8*)dst;
    const uint8 *s = (const uint8*)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        for (uint32 i = 0; i < n; i++) d[i] = s[i];
    } else {
        for (uint32 i = n; i > 0; i--) d[i - 1] = s[i - 1];
    }
    return dst;
}

int memcmp(const void *s1, const void *s2, uint32 n) {
    const uint8_t *a = (const uint8_t *)s1;
    const uint8_t *b = (const uint8_t *)s2;
    size_t count = n;
    if (count == 0) return 0;

#if defined(__x86_64__)
    uint8_t equal;
    /*
     * Large Linux userspace paths compare framebuffer rows, shared-library
     * pages, and socket buffers frequently.  A byte-at-a-time C loop at -O0
     * turns a normal 6 MiB fbdev shadow scan into a visible desktop stall.
     * Keep DF cleared and use the architecture string compare primitive.  The
     * final ZF value, not the remaining count, distinguishes equality: RCX is
     * also zero when the last compared byte is the first mismatch.
     */
    __asm__ __volatile__(
        "cld; repe cmpsb; sete %0"
        : "=qm"(equal), "+S"(a), "+D"(b), "+c"(count)
        :
        : "memory", "cc");
    if (equal) return 0;
    {
        uint8_t av = a[-1];
        uint8_t bv = b[-1];
        return (int)av - (int)bv;
    }
#elif defined(__aarch64__)
    while (count--) {
        uint8_t av = *a++;
        uint8_t bv = *b++;
        if (av != bv) return (int)av - (int)bv;
    }
    return 0;
#else
#error "memcmp needs an architecture implementation"
#endif
}

void *memchr(const void *memory, int value, size_t length) {
    const uint8_t *bytes = (const uint8_t *)memory;
    uint8_t selected = (uint8_t)value;

    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] == selected)
            return (void *)(uintptr_t)&bytes[index];
    }
    return 0;
}

int strlen(const char *s) {
    int len = 0;
    while (*s++)
        len++;
    return len;
}

size_t strnlen(const char *text, size_t maximum) {
    size_t length = 0;

    while (length < maximum && text[length] != '\0')
        ++length;
    return length;
}

char *strrchr(const char *text, int character) {
    const char *match = 0;
    char selected = (char)character;

    do {
        if (*text == selected)
            match = text;
    } while (*text++ != '\0');
    return (char *)(uintptr_t)match;
}

int strcmp(const char *s1, const char *s2) {
    int i = 0;

    while ((s1[i] == s2[i])) {
        if (s2[i++] == 0)
            return 0;
    }
    return 1;
}

int strncmp(const char *s1, const char *s2, int c) {
    int result = 0;

    while (c) {
        result = *s1 - *s2++;
        if ((result != 0) || (*s1++ == 0)) {
            break;
        }
        c--;
    }
    return result;
}

int strcpy(char *dst, const char *src) {
    int i = 0;
    while ((*dst++ = *src++) != 0)
        i++;
    return i;
}

void strcat(char *dest, const char *src) {
    char *end = (char *)dest + strlen(dest);
    memcpy((void *)end, (void *)src, strlen(src));
    end = end + strlen(src);
    *end = '\0';
}

int isspace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

int isalpha(char c) {
    return (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')));
}

char upper(char c) {
    if ((c >= 'a') && (c <= 'z'))
        return (c - 32);
    return c;
}

char lower(char c) {
    if ((c >= 'A') && (c <= 'Z'))
        return (c + 32);
    return c;
}

void itoa(char *buf, int base, int d) {
    uint32_t u = (uint32_t)d;
    int b = 10;
    
    if (base == 'x') b = 16;
    else if (base == 'o') b = 8;
    else if (base == 'd' && d < 0) {
        *buf++ = '-';
        u = (uint32_t)-d;
    }

    char tmp[32];
    int i = 0;
    if (u == 0) tmp[i++] = '0';
    while (u > 0) {
        int r = u % b;
        tmp[i++] = (r < 10) ? (r + '0') : (r - 10 + 'a');
        u /= b;
    }
    while (i > 0) *buf++ = tmp[--i];
    *buf = 0;
}

char *strstr(const char *in, const char *str) {
    char c;
    uint32 len;

    c = *str++;
    if (!c)
        return (char *)in;

    len = strlen(str);
    do {
        char sc;
        do {
            sc = *in++;
            if (!sc)
                return (char *)0;
        } while (sc != c);
    } while (strncmp(in, str, len) != 0);

    return (char *)(in - 1);
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for ( ; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

int atoi(const char *s) {
    int sign = 1;
    int v = 0;
    if (!s) return 0;
    while (*s && isspace(*s)) s++;
    if (*s == '-') {
        sign = -1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return sign * v;
}
