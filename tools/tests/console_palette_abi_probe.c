/* SPDX-License-Identifier: MPL-2.0 */
/* Linux guest ABI probe; restores the original global palette on every exit. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_GIO_CMAP 0x4b70u
#define TEST_PIO_CMAP 0x4b71u
#define TEST_KDGKBTYPE 0x4b33u
#define PALETTE_BYTES 48u

#define REQUIRE(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "console_palette_abi_probe: %s (errno=%d)\n", message, errno); \
        failed = 1; \
        goto cleanup; \
    } \
} while (0)

static int ioctl_error(int descriptor, unsigned long request,
                       void *address, int expected) {
    errno = 0;
    return ioctl(descriptor, request, address) == -1 && errno == expected;
}

int main(void) {
    uint8_t original[PALETTE_BYTES], changed[PALETTE_BYTES];
    uint8_t guarded[PALETTE_BYTES + 2u];
    uint8_t observed[PALETTE_BYTES];
    uint8_t keyboard_type[3] = {0xa5, 0, 0xa5};
    int tty = -1, other = -1, non_tty = -1, pty = -1;
    int saved = 0, failed = 0, status;
    long page_size = sysconf(_SC_PAGESIZE);
    uint8_t *pages = MAP_FAILED;
    pid_t child;

    REQUIRE(page_size >= (long)PALETTE_BYTES, "page size");
    tty = open("/dev/tty0", O_RDWR | O_NOCTTY | O_CLOEXEC);
    REQUIRE(tty >= 0, "open /dev/tty0");
    /* Match kbd getfd(): discovery must succeed before attempting PIO_CMAP. */
    REQUIRE(isatty(tty) && ioctl(tty, TEST_KDGKBTYPE, keyboard_type + 1u) == 0 &&
            (keyboard_type[1] == 1u || keyboard_type[1] == 2u),
            "kbd console discovery (isatty and KDGKBTYPE)");
    REQUIRE(keyboard_type[0] == 0xa5 && keyboard_type[2] == 0xa5,
            "KDGKBTYPE writes exactly one byte");
    REQUIRE(ioctl_error(tty, TEST_KDGKBTYPE, 0, EFAULT), "KDGKBTYPE null pointer");
    REQUIRE(ioctl(tty, TEST_GIO_CMAP, original) == 0, "GIO_CMAP initial");
    saved = 1;
    for (unsigned int i = 0; i < PALETTE_BYTES; ++i)
        changed[i] = (uint8_t)(original[i] ^ (uint8_t)(i * 3u + 1u));
    REQUIRE(ioctl(tty, TEST_PIO_CMAP, changed) == 0,
            "PIO_CMAP (run with CAP_SYS_TTY_CONFIG)");
    memset(guarded, 0xa5, sizeof(guarded));
    REQUIRE(ioctl(tty, TEST_GIO_CMAP, guarded + 1u) == 0, "GIO_CMAP round trip");
    REQUIRE(guarded[0] == 0xa5 && guarded[PALETTE_BYTES + 1u] == 0xa5 &&
            memcmp(guarded + 1u, changed, PALETTE_BYTES) == 0,
            "48-byte RGB round trip and boundaries");
    other = open("/dev/tty63", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    REQUIRE(other >= 0, "open /dev/tty63");
    REQUIRE(ioctl(other, TEST_GIO_CMAP, observed) == 0 &&
            memcmp(observed, changed, PALETTE_BYTES) == 0,
            "global palette visible through another VT");
    REQUIRE(ioctl_error(tty, TEST_GIO_CMAP, 0, EFAULT), "GIO_CMAP null pointer");
    REQUIRE(ioctl_error(tty, TEST_PIO_CMAP, 0, EFAULT), "PIO_CMAP null pointer");

    pages = mmap(0, (size_t)page_size * 2u, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(pages != MAP_FAILED, "map fault boundary");
    REQUIRE(mprotect(pages + page_size, (size_t)page_size, PROT_NONE) == 0,
            "protect fault boundary");
    REQUIRE(ioctl(tty, TEST_KDGKBTYPE, pages + page_size - 1u) == 0 &&
            (pages[page_size - 1u] == 1u || pages[page_size - 1u] == 2u),
            "KDGKBTYPE at last writable byte");
    REQUIRE(ioctl_error(tty, TEST_KDGKBTYPE, pages + page_size, EFAULT),
            "KDGKBTYPE inaccessible page");
    memcpy(pages + page_size - (PALETTE_BYTES - 1u), original, PALETTE_BYTES - 1u);
    REQUIRE(ioctl_error(tty, TEST_PIO_CMAP,
                        pages + page_size - (PALETTE_BYTES - 1u), EFAULT),
            "PIO_CMAP crossing inaccessible page");
    REQUIRE(ioctl(tty, TEST_GIO_CMAP, observed) == 0 &&
            memcmp(observed, changed, PALETTE_BYTES) == 0,
            "faulted set leaves the entire palette unchanged");
    REQUIRE(ioctl_error(tty, TEST_GIO_CMAP,
                        pages + page_size - (PALETTE_BYTES - 1u), EFAULT),
            "GIO_CMAP crossing inaccessible page");
    non_tty = open("/dev/null", O_RDWR | O_CLOEXEC);
    REQUIRE(non_tty >= 0, "open /dev/null");
    REQUIRE(ioctl_error(non_tty, TEST_KDGKBTYPE, keyboard_type + 1u, ENOTTY),
            "KDGKBTYPE non-TTY rejection");
    REQUIRE(ioctl_error(non_tty, TEST_GIO_CMAP, observed, ENOTTY) &&
            ioctl_error(non_tty, TEST_PIO_CMAP, changed, ENOTTY),
            "non-console descriptor rejection");
    pty = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
    REQUIRE(pty >= 0, "open /dev/ptmx");
    REQUIRE(ioctl_error(pty, TEST_KDGKBTYPE, keyboard_type + 1u, ENOTTY),
            "KDGKBTYPE PTY rejection");
    REQUIRE(ioctl_error(pty, TEST_GIO_CMAP, observed, ENOTTY) &&
            ioctl_error(pty, TEST_PIO_CMAP, changed, ENOTTY),
            "PTY descriptor rejection");

    child = fork();
    REQUIRE(child >= 0, "fork permission check");
    if (child == 0) {
        /* Drop both the controlling terminal and root capabilities. */
        if (setsid() < 0 || setgid(65534) < 0 || setuid(65534) < 0) _exit(2);
        if (ioctl(tty, TEST_KDGKBTYPE, keyboard_type + 1u) < 0 ||
            (keyboard_type[1] != 1u && keyboard_type[1] != 2u)) _exit(5);
        if (ioctl(tty, TEST_GIO_CMAP, observed) < 0 ||
            memcmp(observed, changed, PALETTE_BYTES) != 0) _exit(3);
        if (!ioctl_error(tty, TEST_PIO_CMAP, original, EPERM)) _exit(4);
        _exit(0);
    }
    while (waitpid(child, &status, 0) < 0) {
        REQUIRE(errno == EINTR, "wait permission child");
    }
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "unprivileged get allowed and set denied");
    REQUIRE(ioctl(tty, TEST_GIO_CMAP, observed) == 0 &&
            memcmp(observed, changed, PALETTE_BYTES) == 0,
            "denied set leaves palette unchanged");

cleanup:
    if (saved) {
        if (ioctl(tty, TEST_PIO_CMAP, original) < 0 ||
            ioctl(tty, TEST_GIO_CMAP, observed) < 0 ||
            memcmp(observed, original, PALETTE_BYTES) != 0) {
            fprintf(stderr, "console_palette_abi_probe: palette restoration failed\n");
            failed = 1;
        }
    }
    if (pages != MAP_FAILED) munmap(pages, (size_t)page_size * 2u);
    if (pty >= 0) close(pty);
    if (non_tty >= 0) close(non_tty);
    if (other >= 0) close(other);
    if (tty >= 0) close(tty);
    if (!failed) puts("console_palette_abi_probe: PASS");
    return failed;
}
