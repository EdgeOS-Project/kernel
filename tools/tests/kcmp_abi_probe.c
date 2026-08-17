/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux kcmp ABI regression probe. */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_kcmp
#if defined(__x86_64__)
#define SYS_kcmp 312
#elif defined(__aarch64__)
#define SYS_kcmp 272
#else
#error "Unsupported architecture"
#endif
#endif

#define KCMP_FILE 0
#define KCMP_VM 1
#define KCMP_FILES 2
#define KCMP_FS 3
#define KCMP_SIGHAND 4

static long compare(pid_t first, pid_t second, unsigned int type,
                    unsigned long first_index,
                    unsigned long second_index) {
    return syscall(SYS_kcmp, first, second, type,
                   first_index, second_index);
}

int main(void) {
    pid_t self = getpid();
    int descriptor;
    int duplicate;

    descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0) return 1;
    duplicate = dup(descriptor);
    if (duplicate < 0) return 2;
    if (compare(self, self, KCMP_FILE, descriptor, duplicate) != 0)
        return 3;
    if (compare(self, self, KCMP_VM, 0, 0) != 0 ||
        compare(self, self, KCMP_FILES, 0, 0) != 0 ||
        compare(self, self, KCMP_FS, 0, 0) != 0 ||
        compare(self, self, KCMP_SIGHAND, 0, 0) != 0)
        return 4;
    errno = 0;
    if (compare(self, self, KCMP_FILE, (unsigned long)-1,
                descriptor) != -1 || errno != EBADF)
        return 5;
    errno = 0;
    if (compare(self, self, UINT32_MAX, 0, 0) != -1 || errno != EINVAL)
        return 6;
    puts("kcmp ABI: ok");
    return 0;
}
